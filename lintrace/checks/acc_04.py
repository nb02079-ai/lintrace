"""ACC-04 비밀번호 필드 이상.

판정 (위험)
- /etc/passwd 비밀번호 칸이 'x'가 아니고 잠김(*, !)도 아님 — 해시를 passwd에 직접 넣었거나 비어 있음
  (passwd는 누구나 읽을 수 있어 해시가 그대로 노출된다)
- /etc/shadow 비밀번호가 비어 있음 — 비밀번호 없이 로그인
- 약한 해시 방식: DES(13자, '$' 없음), MD5('$1$')
근거에는 해시 내용을 보이지 않고 방식과 길이만 적는다.
"""
import re

from ..collectors.accounts import accounts
from .base import Check, Context, Evidence

DES = re.compile(r"^[./0-9A-Za-z]{13}$")


def locked(pw):
    return pw.startswith(("*", "!"))


def scheme(pw):
    """해시 방식 이름. 약하면 (이름, True)."""
    if pw == "":
        return "비어 있음", True
    if DES.match(pw):
        return "DES", True
    if pw.startswith("$1$"):
        return "MD5", True
    for prefix, name in (("$y$", "yescrypt"), ("$6$", "SHA-512"), ("$5$", "SHA-256"),
                         ("$2", "bcrypt"), ("$7$", "scrypt"), ("$gy$", "gost-yescrypt")):
        if pw.startswith(prefix):
            return name, False
    return "알 수 없는 형식", False


def describe(pw):
    name, _ = scheme(pw)
    return "{} 형식, {}자".format(name, len(pw)) if pw else "비어 있음"


class Acc04(Check):
    id = "ACC-04"
    title = "비밀번호 필드 이상"
    severity = "warning"
    attack = "T1098"

    def run(self, ctx: Context):
        acc = accounts(ctx)
        shadow = acc.shadow()
        findings = []
        for u in acc.users:
            problems, ev = [], []
            if u.password != "x" and not locked(u.password):
                if u.password == "":
                    problems.append("/etc/passwd 비밀번호 칸이 비어 있다 (비밀번호 없이 로그인)")
                else:
                    problems.append("/etc/passwd에 비밀번호 해시가 직접 들어 있다 (누구나 읽을 수 있음)")
                    name, weak = scheme(u.password)
                    if weak:
                        problems.append("해시 방식이 약하다 ({})".format(name))
                ev.append(Evidence("/etc/passwd", "{}행: {} 비밀번호 칸 — {}".format(
                    u.lineno, u.name, describe(u.password))))
            if u.name in shadow:
                pw, no = shadow[u.name]
                if not locked(pw):
                    name, weak = scheme(pw)
                    if pw == "":
                        problems.append("/etc/shadow 비밀번호가 비어 있다 (비밀번호 없이 로그인)")
                    elif weak:
                        problems.append("/etc/shadow 해시 방식이 약하다 ({})".format(name))
                    if pw == "" or weak:
                        ev.append(Evidence("/etc/shadow", "{}행: {} — {}".format(no, u.name, describe(pw))))
            if problems:
                findings.append(self.finding(
                    reason="'{}' 계정: {}".format(u.name, "; ".join(problems)),
                    next_steps="이 계정의 비밀번호를 'passwd'로 다시 정해 shadow에 강한 방식(yescrypt·SHA-512)으로 "
                               "저장하고, 누가 비밀번호 칸을 바꿨는지 확인한다. 해시가 노출됐다면 이미 크랙됐다고 본다.",
                    evidence=ev,
                ))
        self.scope = "계정 {}개, {}".format(
            len(acc.users), "shadow {}개".format(len(shadow)) if acc.has_shadow else "shadow 없음")
        return findings
