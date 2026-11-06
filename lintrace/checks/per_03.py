"""PER-03 rc.local, init.d 스크립트 변경.

/etc/rc.local은 실행 권한이 있으면 systemd의 rc-local.service가 부팅 때 root로 실행한다.
/etc/init.d 스크립트는 systemd-sysv-generator가 서비스로 바꿔 실행한다 (/etc/rc?.d 링크로 켜짐).

판정
- 위험: 실행 권한 있는 rc.local에 명령이 있음 / 패키지에 속하지 않거나 원본과 다른 init.d 스크립트 /
  /etc/rc?.d 링크가 /etc/init.d 밖을 가리킴
- 심각: 내용이 의심 명령, 실행하는 파일이 임시 폴더·숨김 경로·홈, 일반 사용자가 소유하거나 쓸 수 있음
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import Item, executable, file_evidence, file_state, group, owner_issue, regular
from .scriptscan import scan_lines

RC_LOCAL = "/etc/rc.local"
INIT_D = "/etc/init.d"
RC_DIRS = ["/etc/rc{}.d".format(x) for x in "0123456S"]
SKIP = {"README", ".depend.boot", ".depend.start", ".depend.stop", ".legacy-bootordering"}
EXIT0 = re.compile(r"^exit\s+0\s*$")


class Per03(Check):
    id = "PER-03"
    title = "rc.local, init.d 스크립트 변경"
    severity = "warning"
    attack = "T1037.004"

    def run(self, ctx: Context):
        items = []
        rc_note = "rc.local 없음"
        if regular(ctx, RC_LOCAL):
            lines = ctx.read_lines(RC_LOCAL)
            cmds = [(no, l.strip()) for no, l in enumerate(lines, start=1)
                    if l.strip() and not l.strip().startswith("#") and not EXIT0.match(l.strip())]
            if not executable(ctx, RC_LOCAL):
                rc_note = "rc.local 실행 권한 없음 (실행되지 않음)"
            elif not cmds:
                rc_note = "rc.local 명령 없음"
            else:
                rc_note = "rc.local 명령 {}줄".format(len(cmds))
                cond = [("warning", "부팅 때 root로 실행되는 rc.local에 명령 {}줄이 있다".format(len(cmds)))]
                cond += [(s, w) for s, w, _, _ in scan_lines(lines)]
                issue = owner_issue(ctx, RC_LOCAL)
                if issue:
                    cond.append(("critical", issue))
                ev = file_evidence(ctx, RC_LOCAL, *file_state(ctx, RC_LOCAL))
                ev += [Evidence(RC_LOCAL, "{}행: {}".format(no, c)) for no, c in cmds[:8]]
                items.append(Item(RC_LOCAL, cond, ev))

        scripts = 0
        for name in ctx.list_dir(INIT_D):
            path = posixpath.join(INIT_D, name)
            if name in SKIP or name.startswith(".") or not regular(ctx, path):
                continue
            scripts += 1
            state, pkg = file_state(ctx, path)
            cond = []
            if state in ("unpackaged", "modified"):
                cond.append(("warning", "패키지에 속하지 않는 init.d 스크립트" if state == "unpackaged" else
                             "패키지 원본과 다른 init.d 스크립트"))
                hits = scan_lines(ctx.read_lines(path))
                cond += [(s, w) for s, w, _, _ in hits]
            else:
                hits = []
            issue = owner_issue(ctx, path)
            if issue:
                cond.append(("critical", issue))
            if cond:
                ev = file_evidence(ctx, path, state, pkg)
                ev += [Evidence(path, "{}행: {}".format(no, line)) for _, _, no, line in hits[:5]]
                ev += self.links_to(ctx, path)
                items.append(Item(path, cond, ev))

        links = 0
        for d in RC_DIRS:
            for name in ctx.list_dir(d):
                path = posixpath.join(d, name)
                target = ctx.readlink(path)
                if target is None:
                    continue
                links += 1
                real = ctx.realpath(path)
                if posixpath.dirname(real) != INIT_D and real != "/dev/null":
                    items.append(Item(path, [("warning", "부팅 순서 링크가 /etc/init.d 밖({})을 가리킨다".format(real))],
                                      [Evidence(path, "링크 대상: {}".format(target))]))

        findings = group(self, items, "스크립트 내용과 만든 시점·사람을 확인한다. 필요 없으면 실행 권한을 빼거나 "
                                      "'update-rc.d 이름 remove'로 끄기 전에 파일을 보존한다(--out).", "부팅 스크립트")
        self.scope = "{}, init.d 스크립트 {}개, rc?.d 링크 {}개".format(rc_note, scripts, links)
        return findings

    @staticmethod
    def links_to(ctx, script):
        out = []
        for d in RC_DIRS:
            for name in ctx.list_dir(d):
                if name.startswith("S") and ctx.realpath(posixpath.join(d, name)) == script:
                    out.append(Evidence(posixpath.join(d, name), "부팅 때 실행하는 링크"))
        return out[:3]
