"""ACC-08 로그인 실패 연속 후 성공.

비밀번호 대입(brute force)이 성공한 흔적. 같은 IP에서 SSH 로그인 실패가 이어지다가 그 IP로 로그인에
성공했으면, 대입으로 비밀번호를 알아냈을 수 있다.

판정 (심각): 같은 IP에서 실패 FAILURES회 이상 뒤 WINDOW초 안에 같은 IP로 로그인 성공
로그 안의 시각은 사건 순서와 간격을 보는 데만 쓴다 (파일 변경 시각은 쓰지 않는다).
인증 로그가 없으면 점검 불가 (journal은 2-E에서 읽는다).
"""
import re

from ..collectors.authlog import auth_log
from ..timefmt import absolute
from .base import Check, Context, Evidence, Unavailable

FAILURES = 5
WINDOW = 3600
FAILED = re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+)")


def ssh_events(log):
    """[(종류 'fail'/'ok', Entry, 계정, IP, 방식)]"""
    out = []
    for e in log.sshd():
        m = FAILED.match(e.msg)
        if m:
            out.append(("fail", e, m.group(1), m.group(2), None))
            continue
        m = ACCEPTED.match(e.msg)
        if m:
            out.append(("ok", e, m.group(2), m.group(3), m.group(1)))
    out.sort(key=lambda x: x[1].ts)
    return out


def require_log(ctx):
    log = auth_log(ctx)
    if not log.available:
        raise Unavailable("인증 로그 없음 (/var/log/auth.log) — journal 읽기는 2-E에서 추가")
    return log


class Acc08(Check):
    id = "ACC-08"
    title = "로그인 실패 연속 후 성공"
    severity = "critical"
    attack = "T1110"

    def run(self, ctx: Context):
        log = require_log(ctx)
        events = ssh_events(log)
        fails = {}      # IP → [(시각, Entry, 계정)]
        reported = set()
        findings = []
        for kind, e, user, ip, method in events:
            if kind == "fail":
                fails.setdefault(ip, []).append((e.ts, e, user))
                continue
            recent = [f for f in fails.get(ip, []) if e.ts - WINDOW <= f[0] <= e.ts]
            if len(recent) < FAILURES or (ip, user) in reported:
                continue
            reported.add((ip, user))
            tried = sorted({u for _, _, u in recent})
            first, last = recent[0][1], recent[-1][1]
            findings.append(self.finding(
                reason="{}에서 SSH 로그인 실패 {}회 뒤 '{}' 계정으로 로그인 성공 ({}) — 비밀번호 대입이 성공했을 수 있다".format(
                    ip, len(recent), user, method),
                next_steps="이 계정의 비밀번호를 바꾸고 세션을 끊는다. 성공 뒤 이 IP·계정으로 한 일(명령 기록, sudo 기록, "
                           "새로 생긴 파일·계정·키)을 확인하고, 방화벽이나 fail2ban으로 대입을 막는다.",
                evidence=[
                    Evidence(first.source, "{} 첫 실패: {}".format(first.where(), first.raw)),
                    Evidence(last.source, "{} 마지막 실패: {}".format(last.where(), last.raw)),
                    Evidence(e.source, "{} 성공: {}".format(e.where(), e.raw)),
                    Evidence(e.source, "실패 {}회 ({} ~ {}), 시도한 계정 {}개: {}".format(
                        len(recent), absolute(recent[0][0]), absolute(recent[-1][0]), len(tried), ", ".join(tried[:10]))),
                ],
                timestamp=e.ts,
            ))
        n_fail = sum(1 for x in events if x[0] == "fail")
        self.scope = "{}, SSH 실패 {}건·성공 {}건".format(log.scope(), n_fail, len(events) - n_fail)
        return findings
