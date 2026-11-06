"""PER-07 기본 목록에 없는 커널 모듈.

커널 모듈 루트킷(Diamorphine, Reptile 등)은 root 권한으로 커널에 올라가 프로세스·파일·연결을 숨긴다.

보는 것
1. 올라온 모듈(/proc/modules)의 파일: 이 커널의 modules.dep에서 찾은 경로가 /lib/modules/<버전>/kernel 안이고
   패키지 파일인지. 모듈별 taint의 O(트리 밖 모듈). DKMS로 빌드한 모듈(/var/lib/dkms에 등록)은 정상.
   C(staging)·E(서명 없음)만 있는 패키지 모듈은 정상 (lin.security vboxvideo 'CE', 2026-11-06 정답)
   taint O는 근거에 보여준다 (파일 위치·소속으로 판정).
2. 숨긴 모듈: /sys/module/<이름>/initstate(올라온 모듈만 있음)는 있는데 /proc/modules 목록에 없음
3. 자동 로드 설정: /etc/modules, modules-load.d의 패키지 밖·원본과 다른 파일에 적힌 모듈,
   modprobe.d의 'install 모듈 명령'(모듈을 올릴 때 명령을 실행 — /bin/false·/bin/true로 막는 것은 정상)

판정
- 심각: 숨긴 모듈 / install 명령이 의심 명령
- 심각: 패키지 모듈 파일이 원본과 다름
- 위험: 패키지 밖·찾을 수 없는 모듈 파일, 패키지 밖 자동 로드 설정·install 명령
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import Item, exec_conditions, file_evidence, file_state, group, regular

MODULES_LOAD = ["/etc/modules-load.d", "/run/modules-load.d", "/usr/local/lib/modules-load.d",
                "/usr/lib/modules-load.d", "/lib/modules-load.d"]
MODPROBE = ["/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d",
            "/lib/modprobe.d"]
BLOCKERS = re.compile(r"^(?:/usr)?/bin/(?:false|true)\b|^(?:false|true)\b")
DKMS = "/var/lib/dkms"


def norm(name):
    return name.replace("-", "_")


def module_name(path):
    base = posixpath.basename(path)
    return norm(re.sub(r"\.ko(?:\.(?:xz|gz|zst))?$", "", base))


class Per07(Check):
    id = "PER-07"
    title = "기본 목록에 없는 커널 모듈"
    severity = "warning"
    attack = "T1547.006"

    def run(self, ctx: Context):
        release = (ctx.read_lines("/proc/sys/kernel/osrelease", missing_ok=True) or [""])[0].strip()
        base = "/lib/modules/" + release
        dep = {}
        for line in ctx.read_lines(base + "/modules.dep", missing_ok=True) if release else []:
            rel = line.split(":", 1)[0].strip()
            if rel:
                dep.setdefault(module_name(rel), rel)
        loaded = [l.split()[0] for l in ctx.read_lines("/proc/modules") if l.split()]
        loaded_set = {norm(m) for m in loaded}
        dkms = {norm(n) for n in ctx.list_dir(DKMS)}

        items = []
        for name in loaded:
            n = norm(name)
            taint = (ctx.read_lines("/sys/module/{}/taint".format(name), missing_ok=True) or [""])[0].strip()
            rel = dep.get(n)
            cond = []
            ev = [Evidence("/proc/modules", "올라온 모듈 {} (taint {})".format(name, taint or "없음"))]
            if rel is None:
                if n not in dkms:
                    cond.append(("warning", "모듈 {}의 파일이 이 커널({})의 modules.dep에 없다 — insmod로 직접 올렸을 수 "
                                            "있다".format(name, release or "?")))
            else:
                path = posixpath.join(base, rel)
                ev.append(Evidence(path, "모듈 파일"))
                in_tree = rel.startswith("kernel/")
                if n in dkms:
                    pass  # DKMS로 빌드한 모듈 (패키지 파일은 아니지만 등록된 빌드)
                elif not regular(ctx, path):
                    cond.append(("warning", "모듈 {}의 파일 {}가 없다".format(name, path)))
                else:
                    state, pkg = file_state(ctx, path)
                    if state == "unpackaged":
                        cond.append(("warning", "모듈 {}의 파일이 패키지에 속하지 않는다 ({})".format(
                            name, "커널 트리 안" if in_tree else "커널 트리 밖")))
                    elif state == "modified":
                        cond.append(("critical", "모듈 {}의 파일이 패키지({}) 원본과 다르다".format(name, pkg)))
                    ev += file_evidence(ctx, path, state, pkg)
            if cond:
                items.append(Item("/proc/modules/" + name, cond, ev))

        hidden = []
        for name in ctx.list_dir("/sys/module"):
            if norm(name) not in loaded_set and ctx.exists("/sys/module/{}/initstate".format(name)):
                hidden.append(name)
        if hidden:  # 그사이 올라온 모듈을 빼려고 한 번 더 읽는다
            again = {norm(l.split()[0]) for l in ctx.read_lines("/proc/modules") if l.split()}
            hidden = [h for h in hidden if norm(h) not in again]
        for name in hidden:
            items.append(Item("/sys/module/" + name, [("critical", "모듈 {}가 커널에 올라와 있는데(/sys/module) /proc/modules "
                                                                   "목록에서 숨겨져 있다 — 커널 루트킷".format(name))],
                              [Evidence("/sys/module/{}/initstate".format(name), "올라온 모듈에만 있는 파일")]))

        conf_files = 0
        for path in ["/etc/modules"] + [posixpath.join(d, n) for d in MODULES_LOAD for n in ctx.list_dir(d)
                                        if n.endswith(".conf")]:
            if not regular(ctx, path):
                continue
            conf_files += 1
            state, pkg = file_state(ctx, path)
            if state not in ("unpackaged", "modified"):
                continue
            mods = [(no, l.strip()) for no, l in enumerate(ctx.read_lines(path), start=1)
                    if l.strip() and not l.strip().startswith(("#", ";"))]
            if mods:
                items.append(Item(path, [("warning", "부팅 때 자동으로 올릴 모듈 {}개를 적었다 ({})".format(
                    len(mods), ", ".join(m for _, m in mods[:5])))],
                    file_evidence(ctx, path, state, pkg) + [Evidence(path, "{}행: {}".format(no, m)) for no, m in mods[:5]]))

        installs = 0
        for d in MODPROBE:
            for n in ctx.list_dir(d):
                path = posixpath.join(d, n)
                if not n.endswith(".conf") or not regular(ctx, path):
                    continue
                conf_files += 1
                state, pkg = None, None
                for no, raw in enumerate(ctx.read_lines(path), start=1):
                    parts = raw.strip().split(None, 2)
                    if len(parts) < 3 or parts[0] != "install":
                        continue
                    installs += 1
                    cmd = parts[2]
                    if BLOCKERS.match(cmd):
                        continue
                    if state is None:
                        state, pkg = file_state(ctx, path)
                    if state not in ("unpackaged", "modified"):
                        continue
                    cond = [("warning", "모듈 {}를 올릴 때 명령을 실행한다: {}".format(parts[1], cmd[:150]))]
                    first = cmd.split()[0] if cmd.split() else ""
                    cond += exec_conditions(ctx, cmd, first)
                    items.append(Item(path, cond, file_evidence(ctx, path, state, pkg) +
                                      [Evidence(path, "{}행: {}".format(no, raw.strip()))]))

        findings = group(self, items, "모듈의 정체를 확인한다('modinfo 이름', 파일 해시). 모르는 모듈은 내리기('rmmod') 전에 "
                                      "메모리·파일을 보존하고, 숨긴 모듈이 있으면 이 시스템의 도구 결과를 믿지 말고 외부 매체로 "
                                      "부팅해 다시 본다.", "커널 모듈")
        self.scope = "올라온 모듈 {}개 (커널 {}), 자동 로드·modprobe 설정 {}개, install 줄 {}개".format(
            len(loaded), release or "?", conf_files, installs)
        return findings
