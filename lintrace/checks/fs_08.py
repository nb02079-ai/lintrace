"""FS-08 비정상 숨김 디렉터리.

'.'으로 시작하는 폴더는 ls에 바로 보이지 않아 공격자가 도구를 숨기는 데 쓴다 (/tmp/.x, /usr/lib/.lib,
/var/tmp/... 등). 사용자 홈의 숨김 폴더(.cache, .config 등)는 정상이라 보지 않는다.

정상 (2026-11-06 정답): 패키지에 속한 폴더(vdso/.build-id, linux-headers/.tmp_versions),
개발·패키지 도구의 폴더(.git·.github·node_modules/.bin 등 — /dev/shm 제외),
/tmp의 X 폴더(.X11-unix, .ICE-unix, .XIM-unix, .font-unix, .Test-unix), 컨테이너·snap 저장소 안쪽
판정
- 위험: 시스템 영역에 패키지에 속하지 않는 숨김 폴더
- 심각: 이름이 '...'·공백·제어 문자처럼 눈속임인 폴더, /dev 아래(/dev/shm)의 숨김 폴더
"""
import os
import posixpath

from ..collectors.filewalk import filewalk, require_root
from ..collectors.packages import packages
from .base import Check, Context, Evidence, Unavailable
from .persist import RANK, Item, uid_name

X_DIRS = {"/tmp/.X11-unix", "/tmp/.ICE-unix", "/tmp/.XIM-unix", "/tmp/.font-unix", "/tmp/.Test-unix"}
HOMES = ("/home/", "/root/")
# 개발·패키지 관리 도구가 만드는 숨김 폴더 (.git, node_modules/.bin 등) — 이 이름이거나 이런 트리 안쪽이면 정상
TOOL_NAMES = {".git", ".github", ".gitlab", ".svn", ".hg", ".bzr", ".circleci", ".husky", ".well-known", ".bin",
              ".vscode", ".idea", ".devcontainer", ".changeset", ".storybook", ".yarn", ".pnpm"}
TOOL_TREES = {"node_modules", "site-packages", "dist-packages", "vendor", "testdata", "__pycache__", ".git"}
CONTAINERS = ("/var/lib/docker/", "/var/lib/containerd/", "/var/lib/lxd/", "/var/lib/lxc/", "/var/snap/",
              "/var/lib/snapd/", "/var/lib/containers/")


def deceptive(name):
    return name.strip(".") == "" or name != name.strip() or any(c.isspace() or ord(c) < 32 for c in name)


class Fs08(Check):
    id = "FS-08"
    title = "비정상 숨김 디렉터리"
    severity = "warning"
    attack = "T1564.001"

    def run(self, ctx: Context):
        w = filewalk(ctx)
        if require_root(w):
            raise Unavailable("디렉터리 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(w.denied)))
        db = packages(ctx)
        reported, items, normal = [], [], 0
        for path, st in w.hidden:
            if path.startswith(HOMES) or path == "/root" or path.startswith(CONTAINERS):
                continue
            if any(path.startswith(r + "/") for r in reported):
                continue  # 이미 낸 숨김 폴더 안쪽
            name = posixpath.basename(path)
            parts = path.split("/")
            tool = not path.startswith("/dev/") and (name in TOOL_NAMES or any(p in TOOL_TREES for p in parts[:-1]))
            if path in X_DIRS or tool or db.owner(path):
                normal += 1
                continue
            cond = [("warning", "시스템 영역에 패키지에 속하지 않는 숨김 폴더가 있다")]
            if deceptive(name):
                cond.append(("critical", "이름이 '{}' — 점·공백으로 눈속임한 폴더".format(name.replace("\n", "\\n"))))
            if path.startswith("/dev/"):
                cond.append(("critical", "메모리 파일시스템(/dev/shm)의 숨김 폴더"))
            try:
                names = sorted(os.listdir(ctx.path(path)))
            except OSError:
                names = []
            ev = [Evidence(path, "소유자 {}, 권한 {:o}".format(uid_name(ctx, st.st_uid), st.st_mode & 0o7777)),
                  Evidence(path, "안의 항목 {}개{}".format(len(names), ": " + ", ".join(names[:8]) if names else ""))]
            items.append(Item(path, cond, ev))
            reported.append(path)
        findings = []
        if items:  # 폴더마다 위치가 흩어져 있어 한 건으로 묶는다
            items.sort(key=lambda it: (-RANK[it.severity], it.path))
            sev = items[0].severity
            ev = []
            for it in items[:15]:
                ev.append(Evidence(it.path, "; ".join(c[1] for c in it.conditions)))
                ev += it.evidence
            findings.append(self.finding(
                reason="시스템 영역에 패키지에 속하지 않는 숨김 폴더 {}개: {}".format(
                    len(items), ", ".join(it.path for it in items[:10]) + (" 외" if len(items) > 10 else "")),
                next_steps="안의 파일을 보존하고(--out) 정체를 확인한다(ELF면 FS-01, 스크립트면 내용). 누가 만들었는지는 "
                           "소유자와 명령 기록(CMD-01)으로 본다.",
                evidence=ev[:30], severity=sev))
        self.scope = "시스템 영역 숨김 폴더 {}개 (정상 {}개)".format(len(items) + normal, normal)
        return findings
