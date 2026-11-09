"""LOG-02 wtmp·btmp 로그인 기록 삭제·불일치.

/var/log/wtmp(성공한 로그인·부팅), /var/log/btmp(실패한 로그인)는 last·lastb가 읽는 바이너리 기록이다.
공격자는 자기 로그인 줄을 지우거나(utmpdump로 편집 후 되쓰기) 파일을 비운다. 파일 날짜가 아니라, 인증 로그·
journal에 남은 로그인과 맞대어 '한쪽에만 있는' 기록으로 삭제를 찾는다 (2026-11-09 결정).

판정
- 심각: wtmp가 다루는 기간 안의 SSH 로그인 성공이 인증 로그·journal에는 있는데 wtmp에는 없다 (지워진 흔적)
- 심각: 인증 로그·journal에 로그인이 있는데 wtmp 파일이 아예 없다
- 위험: 파일 크기가 레코드 크기(384바이트)의 배수가 아니다 (잘림·편집 흔적)
정상
- 모든 기록이 같은 시점부터 시작 (배포 전 /var/log를 비운 서버) — 범위에 시작 시각만
- 순환으로 지워진 오래된 기간의 로그인은 비교하지 않는다 (wtmp 시작 이전)
"""
from ..collectors.utmp import RECORD, btmp, wtmp
from ..timefmt import absolute
from .acc_08 import ssh_events
from .base import Check, Context, Evidence
from ..collectors.authlog import auth_log

TOLERANCE = 300     # 인증 로그와 wtmp 시각 차이 허용 (초)


class Log02(Check):
    id = "LOG-02"
    title = "wtmp·btmp 로그인 기록 삭제·불일치"
    severity = "critical"
    attack = "T1070.002"

    def run(self, ctx: Context):
        w, b = wtmp(ctx), btmp(ctx)
        log = auth_log(ctx)
        logins = [e for kind, e, u, ip, m in ssh_events(log) if kind == "ok"]
        findings = []

        if logins:
            user_logins = w.user_logins() if w.present else []
            login_ts = sorted(l.ts for l in user_logins if l.ts > 0)
            begin = w.begins()
            missing = []
            for e in logins:
                if not w.present:
                    missing.append(e)
                    continue
                if begin is not None and e.ts < begin - TOLERANCE:
                    continue  # wtmp 시작 이전 — 순환으로 지워진 기간
                if not any(abs(e.ts - t) <= TOLERANCE for t in login_ts):
                    missing.append(e)
            if missing:
                findings.append(self.finding(
                    reason=("인증 로그·journal에는 SSH 로그인 성공 {}건이 있는데 /var/log/wtmp에 대응하는 기록이 없다{}"
                            " — 로그인 기록을 지운 흔적").format(
                        len(missing), " (wtmp 파일 자체가 없음)" if not w.present else ""),
                    next_steps="'last -f /var/log/wtmp'로 남은 기록을 보고, 인증 로그·journal의 로그인 시각과 맞대어 "
                               "지워진 세션을 찾는다. wtmp를 증거로 보존한다(--out). utmpdump로 편집한 흔적인지 본다.",
                    evidence=[Evidence(e.source, "{}: {} (로그인 {})".format(e.where(), e.raw[:160], absolute(e.ts)))
                              for e in missing[:8]]))

        for u in (w, b):
            if u.present and not u.aligned:
                findings.append(self.finding(
                    reason="{} 크기가 레코드 크기({}바이트)의 배수가 아니다 ({:,}바이트) — 잘리거나 편집된 흔적".format(
                        u.path, RECORD, u.size),
                    next_steps="파일을 보존하고(--out) 'utmpdump {}'로 내용을 확인한다.".format(u.path),
                    evidence=[Evidence(u.path, "크기 {:,}바이트, 나머지 {}바이트".format(u.size, u.size % RECORD))],
                    severity="warning"))

        parts = []
        for name, u in (("wtmp", w), ("btmp", b)):
            if not u.present:
                parts.append(name + " 없음")
            else:
                begin = u.begins()
                parts.append("{} 로그인 {}건{}".format(
                    name, len([l for l in u.logins if l.type == 7 and l.user]),
                    ", 시작 " + absolute(begin) if begin else ""))
        self.scope = ", ".join(parts)
        return findings
