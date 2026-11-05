"""ACC-09 평소와 다른 출처의 SSH 로그인.

계정마다 로그인 성공 출처(IP)를 시간 순서로 본다. 다른 출처로 이미 BASELINE회 이상 로그인해 '평소'가
있는 계정에, 처음 보는 IP로 로그인이 성공하면 참고로 알린다. 탈취한 비밀번호·키로 들어온 경우를 찾는
단서이지만 정상(새 사무실, VPN 변경)도 많아 판정에는 영향을 주지 않는다.

시간대(새벽 로그인 등)는 서버 시간대와 사용자 습관을 알 수 없어 보지 않는다.
"""
from ..timefmt import absolute
from .acc_08 import require_log, ssh_events
from .base import Check, Context, Evidence

BASELINE = 3


class Acc09(Check):
    id = "ACC-09"
    title = "평소와 다른 출처·시간대의 SSH 로그인"
    severity = "info"
    attack = "T1078"

    def run(self, ctx: Context):
        log = require_log(ctx)
        seen = {}       # 계정 → {IP: 횟수}
        findings = []
        logins = 0
        for kind, e, user, ip, method in ssh_events(log):
            if kind != "ok":
                continue
            logins += 1
            history = seen.setdefault(user, {})
            others = sum(n for k, n in history.items() if k != ip)
            if ip not in history and others >= BASELINE:
                usual = ", ".join("{}({}회)".format(k, n) for k, n in sorted(history.items(), key=lambda x: -x[1])[:5])
                findings.append(self.finding(
                    reason="'{}' 계정이 처음 보는 출처 {}에서 로그인했다 (이전 출처: {})".format(user, ip, usual),
                    next_steps="본인 접속인지 확인한다. 아니면 이 세션에서 한 일(명령 기록, sudo 기록)을 보고 "
                               "비밀번호·키를 바꾼다.",
                    evidence=[Evidence(e.source, "{}: {}".format(e.where(), e.raw)),
                              Evidence(e.source, "로그인 시각 {}, 방식 {}".format(absolute(e.ts), method))],
                    timestamp=e.ts,
                ))
            history[ip] = history.get(ip, 0) + 1
        self.scope = "{}, SSH 로그인 성공 {}건·계정 {}개".format(log.scope(), logins, len(seen))
        return findings
