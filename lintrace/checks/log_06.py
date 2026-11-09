"""LOG-06 시각 조작 의심.

공격자는 흔적의 시각을 흐리려고 시스템 시계를 뒤로 돌리거나(date -s, timedatectl) 파일 시각을 조작한다
(touch -t). 두 가지로 본다.
- journal: 같은 부팅 안에서 단조 시각(부팅 뒤 흐른 시간)은 늘었는데 실시간(벽시계)이 크게 뒤로 감
  (NTP 소폭 보정은 5분 안이라 넘는 것만). 부팅과 부팅 사이는 당연히 다르므로 한 부팅 안에서만 본다.
- 파일: 시스템 영역에 변경 시각이 지금보다 하루 넘게 미래인 파일 (시간 원칙 — 미래 시각만 조작 흔적)

판정: 위험
"""
from ..collectors.filewalk import filewalk, require_root
from ..collectors.journal import journal
from ..timefmt import absolute, describe
from .base import Check, Context, Evidence, Unavailable
from .persist import uid_name

BACKWARD = 300      # 실시간이 이보다 더 뒤로 가면 조작 의심 (초)


class Log06(Check):
    id = "LOG-06"
    title = "시각 조작 의심"
    severity = "warning"
    attack = "T1070.006"

    def run(self, ctx: Context):
        findings = []
        j = journal(ctx)
        jumps = []
        if j.available:
            for boot, recs in j.boots().items():
                timed = sorted((r for r in recs if r.monotonic is not None), key=lambda r: r.monotonic)
                for a, b in zip(timed, timed[1:]):
                    drift = (b.realtime - a.realtime) - (b.monotonic - a.monotonic)
                    if drift < -BACKWARD:
                        jumps.append((a, b, drift))
        if jumps:
            jumps.sort(key=lambda x: x[2])
            a, b, drift = jumps[0]
            findings.append(self.finding(
                reason="한 부팅 안에서 시스템 시계가 {:.0f}분 뒤로 돌아갔다 (기록은 계속 쌓이는데 시각만 과거로) — 시각 조작 의심, "
                       "총 {}곳".format(-drift / 60, len(jumps)),
                next_steps="'journalctl'에서 시각이 튀는 구간의 앞뒤 기록과 그 시각의 로그인·명령(CMD-01)을 본다. "
                           "NTP 로그(chrony·systemd-timesyncd)에 보정 기록이 있는지 확인한다.",
                evidence=[Evidence("journal", "직전 {}: [{}] {}".format(absolute(a.realtime), a.prog, a.msg[:100])),
                          Evidence("journal", "직후 {}: [{}] {}".format(absolute(b.realtime), b.prog, b.msg[:100]))]))

        w = filewalk(ctx)
        if require_root(w):
            if not findings:
                raise Unavailable("디렉터리 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(w.denied)))
        if w.future:
            findings.append(self.finding(
                reason="변경 시각이 미래인 파일 {}개 — 파일 시각을 조작한 흔적일 수 있다".format(len(w.future)),
                next_steps="파일 내용과 ctime(속성 변경 시각)을 확인한다. 'touch -t'로 시각을 바꾼 것이면 실제 생성 시점을 "
                           "로그·명령 기록으로 찾는다.",
                evidence=[Evidence(p, "변경 시각 {}, 소유자 {}".format(describe(st.st_mtime, ctx.now)[0], uid_name(ctx, st.st_uid)))
                          for p, st in w.future[:10]]))

        self.scope = "journal {}, 미래 시각 파일 {}개".format(
            "기록 {:,}건".format(len(j.records)) if j.available else "읽기 불가", len(w.future))
        return findings
