"""LOG-03 명령 기록이 /dev/null이거나 비어 있음.

공격자는 자기 명령을 숨기려고 셸 기록을 /dev/null로 연결하거나(ln -sf /dev/null ~/.bash_history) 비운다.
셸 초기화 파일에서 기록을 끄는 설정(unset HISTFILE 등)은 PER-04가 본다 — 여기서는 기록 파일 자체를 본다.

판정 (위험)
- 명령 기록 파일이 /dev/null(또는 다른 장치·심볼릭 링크)로 연결돼 있음
- 로그인 셸을 쓰는 계정인데 기록 파일이 0바이트 (비운 흔적 — 한 번도 안 쓴 계정은 파일이 아예 없다)
파일이 없는 것은 탐지하지 않는다 (대화형 로그인을 안 한 계정도 흔하다).
"""
import stat

from ..collectors.history import FILES, NOLOGIN, accounts
from .base import Check, Context, Evidence
from .persist import group, Item, uid_name


class Log03(Check):
    id = "LOG-03"
    title = "명령 기록이 /dev/null이거나 비어 있음"
    severity = "warning"
    attack = "T1070.003"

    def run(self, ctx: Context):
        items, checked = [], 0
        for user, home, shell in accounts(ctx):
            interactive = not (shell in NOLOGIN or shell.endswith("nologin") or shell.endswith("false"))
            for name in FILES:
                path = home.rstrip("/") + "/" + name
                link = ctx.readlink(path)
                st = ctx.stat(path)
                if link is None and st is None:
                    continue
                checked += 1
                cond = []
                if link is not None:
                    real = ctx.realpath(path)
                    if real != path:
                        cond.append(("warning", "명령 기록이 {}(으)로 연결돼 있다 — 입력한 명령이 저장되지 않고 버려진다".format(real)))
                elif st is not None and stat.S_ISREG(st.st_mode) and st.st_size == 0 and interactive:
                    cond.append(("warning", "로그인 셸({})을 쓰는 계정의 명령 기록이 0바이트다 — 비운 흔적일 수 있다".format(shell)))
                if cond:
                    ev = [Evidence(path, "소유자 {}, {}".format(
                        uid_name(ctx, st.st_uid) if st else "?",
                        "→ " + ctx.realpath(path) if link else "0바이트"))]
                    items.append(Item(path, cond, ev))
        findings = group(self, items, "링크·빈 파일을 언제 누가 만들었는지 파일 ctime과 명령 기록(CMD-01)·로그인(ACC-09)으로 "
                                      "본다. 셸 초기화 파일의 기록 끄기 설정(PER-04)과 함께 확인한다.", "명령 기록 파일")
        self.scope = "명령 기록 파일 {}개".format(checked)
        return findings
