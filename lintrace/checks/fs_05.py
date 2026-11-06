"""FS-05 시스템 바이너리 경로의 패키지 밖 파일.

/bin·/sbin·/usr/bin·/usr/sbin의 파일은 거의 모두 패키지가 설치한다. 패키지 밖 파일은 공격자가 남긴 도구·뒷문일 수 있다.

정상 (2026-11-06 정답)
- 대체 링크(/etc/alternatives — awk, vi, nc 등): 링크를 따라간 실제 파일이 패키지 파일
- dpkg diversion(/bin/sh.distrib — dash 등)
판정
- 위험: 패키지에 속하지 않는 파일·링크
- 심각: 숨김 이름(.으로 시작), 셸 복사본(패키지 셸과 내용이 같음), 링크가 임시 폴더·숨김 경로·홈을 가리킴
/usr/local/bin·sbin(2026-11-06 결정 3): 원래 패키지 밖 프로그램을 두는 곳이라 파일만으로는 탐지하지 않는다.
PATH에서 /usr/bin보다 먼저 찾으므로 시스템 명령과 같은 이름이면 그 명령을 가로챈다 → 위험.
"""
import posixpath
import stat

from ..collectors.packages import packages
from .base import Check, Context, Evidence, Unavailable
from .persist import Item, file_evidence, group, target_issues, unique_dirs

SYSTEM = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
LOCAL = ["/usr/local/bin", "/usr/local/sbin"]
SHELLS = ["/bin/bash", "/bin/dash", "/bin/sh", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh", "/bin/busybox",
          "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/busybox"]


def kind(ctx, path):
    head = ctx.read_head(path, 4)
    if head == b"\x7fELF":
        return "ELF 실행 파일"
    if head[:2] == b"#!":
        return "스크립트"
    return "기타 파일"


class Fs05(Check):
    id = "FS-05"
    title = "시스템 바이너리 경로의 패키지 밖 파일"
    severity = "warning"
    attack = "T1554"

    def run(self, ctx: Context):
        db = packages(ctx)
        if not db.available:
            raise Unavailable("dpkg 정보(/var/lib/dpkg/info)가 없음 — Debian·Ubuntu 계열만 지원")
        shells = {}
        for sh in SHELLS:
            real = ctx.realpath(sh)
            if real not in shells.values() and db.owner(real):
                digest = ctx.sha256(real)
                if digest:
                    shells[digest] = real

        items, total, links = [], 0, 0
        sys_names = set()
        for d in unique_dirs(ctx, SYSTEM):
            for name in ctx.list_dir(d):
                path = posixpath.join(d, name)
                try:
                    st = ctx.stat(path)
                except Unavailable:
                    continue
                if st is None or stat.S_ISDIR(st.st_mode):
                    continue
                total += 1
                sys_names.add(name)
                if db.owner(path) or db.diversion(path):
                    continue
                if stat.S_ISLNK(st.st_mode):
                    real = ctx.realpath(path)
                    if db.owner(real) or db.diversion(real):
                        links += 1  # 대체 링크 등
                        continue
                    cond = [("warning", "패키지에 속하지 않는 링크 → {}".format(real))]
                    cond += [c for c in target_issues(ctx, real) if c[0] == "critical"]
                    items.append(Item(path, cond, [Evidence(path, "링크 대상: {} (실제 {})".format(ctx.readlink(path), real))]))
                    continue
                cond = [("warning", "패키지에 속하지 않는 {}".format(kind(ctx, path)))]
                if name.startswith("."):
                    cond.append(("critical", "숨김 이름의 파일이다"))
                digest = ctx.sha256(path)
                if digest and digest in shells:
                    cond.append(("critical", "셸 {}의 복사본이다 (내용 같음)".format(shells[digest])))
                ev = file_evidence(ctx, path, "unpackaged", None)
                ev.append(Evidence(path, "SHA-256: {}".format(digest or "계산 불가")))
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    ev.append(Evidence(path, "SUID·SGID 파일 (FS-02에서도 확인)"))
                items.append(Item(path, cond, ev))

        local_total = 0
        for d in unique_dirs(ctx, LOCAL):
            for name in ctx.list_dir(d):
                path = posixpath.join(d, name)
                try:
                    st = ctx.stat(path)
                except Unavailable:
                    continue
                if st is None or stat.S_ISDIR(st.st_mode):
                    continue
                local_total += 1
                if name in sys_names:
                    ev = file_evidence(ctx, path, "unpackaged", None)
                    ev.append(Evidence(path, "SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))
                    items.append(Item(path, [("warning", "시스템 명령 {}와 같은 이름이다 — PATH에서 먼저 찾으므로 그 명령을 "
                                                         "가로챈다".format(name))], ev))

        findings = group(self, items, "파일의 정체(해시 검색, 'strings', 만든 시점)를 확인하고 보존한다(--out). 관리자가 직접 설치한 "
                                      "프로그램이면 /usr/local이나 /opt로 옮기는 것이 원칙이다.", "파일")
        self.scope = "시스템 경로 파일 {:,}개 (대체 링크 {}개 정상), /usr/local 파일 {}개".format(total, links, local_total)
        return findings
