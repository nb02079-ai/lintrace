"""ACC-03 시스템 계정에 로그인 셸 부여.

UID 1~999(그리고 nobody)는 서비스용 계정이라 보통 셸이 nologin·false다. 공격자는 이런 계정에
셸을 주고 비밀번호나 키를 넣어 눈에 덜 띄는 뒷문으로 쓴다.

판정 (위험): 시스템 계정의 셸이 nologin·false가 아님 (빈 칸은 /bin/sh로 로그인되므로 포함)
제외: sync(/bin/sync), halt, shutdown — 전통적으로 해당 명령이 셸 자리에 있는 기본 계정
      postgres(bash·sh) — Debian·Ubuntu postgresql 패키지가 처음부터 셸을 주는 계정 (바뀐 것이 아님)
"""
from ..collectors.accounts import accounts
from .acc_01 import mask_passwd_line
from .base import Check, Context, Evidence

NO_LOGIN = ("nologin", "false")
EXCEPTIONS = {("sync", "sync"), ("halt", "halt"), ("shutdown", "shutdown"),
              ("postgres", "bash"), ("postgres", "sh")}


def is_login_shell(shell):
    name = shell.rsplit("/", 1)[-1]
    return not any(name == n for n in NO_LOGIN)


class Acc03(Check):
    id = "ACC-03"
    title = "시스템 계정에 로그인 셸 부여"
    severity = "warning"
    attack = "T1098"

    def run(self, ctx: Context):
        acc = accounts(ctx)
        system = [u for u in acc.users if u.is_system]
        findings = []
        for u in system:
            if not is_login_shell(u.shell):
                continue
            if (u.name, u.shell.rsplit("/", 1)[-1]) in EXCEPTIONS:
                continue
            shell = u.shell or "(빈 칸 — /bin/sh로 로그인)"
            findings.append(self.finding(
                reason="시스템 계정 '{}'(UID {})의 셸이 {}이라 로그인할 수 있다".format(u.name, u.uid, shell),
                next_steps="이 서비스 계정에 셸이 필요한지 확인한다. 필요 없으면 'usermod -s /usr/sbin/nologin'. "
                           "이 계정의 비밀번호(shadow)·authorized_keys·로그인 기록도 함께 본다.",
                evidence=[Evidence("/etc/passwd", "{}행: {}".format(u.lineno, mask_passwd_line(u.line)))],
            ))
        self.scope = "시스템 계정 {}개".format(len(system))
        return findings
