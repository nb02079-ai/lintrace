"""PER-09 update-motd.d 스크립트 변조.

SSH·콘솔로 로그인할 때마다 pam_motd가 'run-parts --lsbsysinit /etc/update-motd.d'를 root로 실행한다.
누가 로그인하든(일반 사용자라도) root로 도는 지속성 위치다.

판정
- 위험: 실행 권한 있는 스크립트가 패키지에 속하지 않거나 패키지 원본과 다름
- 심각: 의심 명령, 일반 사용자가 소유하거나 쓸 수 있음
범위에 개수만: 실행 권한 없는 파일(run-parts가 건너뜀 — lin.security logo), 지워진 패키지 스크립트
(lin.security 12개, 2026-11-06 정답). pam_motd 사용 여부도 범위에 표시한다.
"""
import posixpath
import re

from ..collectors.packages import packages
from .base import Check, Context, Evidence
from .persist import Item, executable, file_evidence, file_state, group, owner_issue, regular
from .scriptscan import scan_lines

MOTD = "/etc/update-motd.d"
# run-parts가 실행하는 이름 ('.'이 들어간 *.dpkg-old 등은 건너뜀)
LSB_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
PAM_FILES = ["/etc/pam.d/sshd", "/etc/pam.d/login"]


class Per09(Check):
    id = "PER-09"
    title = "update-motd.d 스크립트 변조"
    severity = "warning"
    attack = "T1037"

    def run(self, ctx: Context):
        items, scripts, not_exec = [], 0, 0
        present = set()
        for name in ctx.list_dir(MOTD):
            path = posixpath.join(MOTD, name)
            if not regular(ctx, path):
                continue
            present.add(path)
            if not LSB_NAME.match(name):
                continue
            if not executable(ctx, path):
                not_exec += 1
                continue
            scripts += 1
            state, pkg = file_state(ctx, path)
            cond, hits = [], []
            if state in ("unpackaged", "modified"):
                cond.append(("warning", "로그인 때마다 root로 실행되는 스크립트가 {}".format(
                    "패키지에 속하지 않는다" if state == "unpackaged" else "패키지({}) 원본과 다르다".format(pkg))))
                hits = scan_lines(ctx.read_lines(path))
                cond += [(s, w) for s, w, _, _ in hits]
            issue = owner_issue(ctx, path)
            if issue:
                cond.append(("critical", issue))
            if cond:
                items.append(Item(path, cond, file_evidence(ctx, path, state, pkg) +
                                  [Evidence(path, "{}행: {}".format(no, line)) for _, _, no, line in hits[:5]]))

        deleted = sorted(p for p in packages(ctx).conffiles() if p.startswith(MOTD + "/") and p not in present)
        pam = [f for f in PAM_FILES if any("pam_motd" in l and not l.strip().startswith("#")
                                            for l in ctx.read_lines(f, missing_ok=True))]
        findings = group(self, items, "스크립트 내용을 원본과 비교하고(같은 버전 패키지의 파일), 누가 언제 바꿨는지 확인한다. "
                                      "필요 없으면 보존한 뒤(--out) 실행 권한을 뺀다.", "motd 스크립트")
        notes = ["실행 스크립트 {}개".format(scripts)]
        if not_exec:
            notes.append("실행 권한 없는 파일 {}개(실행 안 됨)".format(not_exec))
        if deleted:
            notes.append("지워진 패키지 스크립트 {}개".format(len(deleted)))
        notes.append("pam_motd 사용: {}".format(", ".join(posixpath.basename(f) for f in pam) if pam else "없음"))
        self.scope = ", ".join(notes)
        return findings
