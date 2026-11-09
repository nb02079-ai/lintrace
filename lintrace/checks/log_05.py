"""LOG-05 journal 시간 공백 구간.

로그를 통째로 지우면(journalctl --rotate --vacuum, 파일 삭제) 한 부팅 안에 기록이 없는 구간이 생긴다.
cron·systemd 타이머가 주기적으로 남기는 기록 덕분에, 켜져 있는 서버의 로그에는 긴 공백이 드물다.

판정 (한 부팅 안에서만 — 부팅과 부팅 사이 공백은 꺼져 있던 시간이라 정상)
- 위험: 기록 공백이 기준 시간을 넘음 (cron이 있으면 2시간, 없으면 6시간)
- 심각: 그 공백 바로 앞뒤에 로그인·sudo 기록이 있음 (침입 세션 동안 로그를 지운 모양)
시각은 단조 시각(부팅 뒤 흐른 시간)으로 재서 시각 조작의 영향을 받지 않는다.
"""
from ..collectors.journal import journal
from ..collectors.processes import processes
from ..timefmt import absolute
from .base import Check, Context, Evidence

CRON_GAP = 2 * 3600
NOCRON_GAP = 6 * 3600
NEAR = 120      # 공백 경계에서 이 시간 안의 로그인·sudo 기록을 본다
SESSION = ("sshd", "sshd-session", "sudo", "login", "systemd-logind", "su")
SESSION_MSG = ("session opened", "Accepted ", "COMMAND=", "new session", "login")


def has_cron(ctx):
    if any(p.name in ("cron", "crond") for p in processes(ctx).procs):
        return True
    for d in ("/etc/cron.hourly", "/etc/cron.d"):
        if [n for n in ctx.list_dir(d) if not n.startswith(".")]:
            return True
    return False


def session_like(r):
    if r.prog in SESSION:
        return True
    return any(s in r.msg for s in SESSION_MSG)


class Log05(Check):
    id = "LOG-05"
    title = "journal 시간 공백 구간"
    severity = "warning"
    attack = "T1070.002"

    def run(self, ctx: Context):
        j = journal(ctx)
        if not j.available:
            self.scope = "journal 읽기 불가 ({})".format(j.note)
            return []
        threshold = CRON_GAP if has_cron(ctx) else NOCRON_GAP
        findings, maxima = [], []
        for boot, recs in j.boots().items():
            timed = sorted((r for r in recs if r.monotonic is not None), key=lambda r: r.monotonic)
            if len(timed) < 2:
                continue
            boot_max = 0
            for a, b in zip(timed, timed[1:]):
                gap = b.monotonic - a.monotonic
                boot_max = max(boot_max, gap)
                if gap > threshold:
                    near_login = any(session_like(r) for r in timed
                                     if a.monotonic - NEAR <= r.monotonic <= a.monotonic
                                     or b.monotonic <= r.monotonic <= b.monotonic + NEAR)
                    findings.append(self.finding(
                        reason="부팅 기록 중간에 {:.1f}시간 동안 아무 기록이 없다 ({} ~ {}){}".format(
                            gap / 3600, absolute(a.realtime), absolute(b.realtime),
                            " — 공백 앞뒤에 로그인·sudo 기록이 있다" if near_login else ""),
                        next_steps="그 시간대에 로그가 지워졌는지 확인한다('journalctl --verify', 원격 로그 서버·"
                                   "/var/log 파일과 비교). cron·타이머 기록까지 비어 있으면 통째로 지운 것이다.",
                        evidence=[Evidence("journal", "직전 기록 {}: [{}] {}".format(absolute(a.realtime), a.prog, a.msg[:120])),
                                  Evidence("journal", "직후 기록 {}: [{}] {}".format(absolute(b.realtime), b.prog, b.msg[:120]))],
                        severity="critical" if near_login else "warning"))
            maxima.append(boot_max)
        self.scope = "부팅 {}개, 기준 {}시간, 부팅별 최대 공백 {}".format(
            len(maxima), threshold // 3600,
            ", ".join("{:.0f}초".format(m) for m in maxima[:6]) if maxima else "없음")
        return findings
