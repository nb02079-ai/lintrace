"""시간 상관분석 (3단계 3차).

탐지된 흔적마다 '언제'를 뽑아 시간 순으로 세워 공격 진행 순서를 재구성한다. 54개 점검 코드는 건드리지
않고(기준선·HTML과 같은 방식), 완성된 탐지 목록(findings)과 Context만 받는다.

시각 출처
- Finding.timestamp가 있으면(ACC-08·09 로그인·로그 사건) 그 시각
- 근거(Evidence)의 source가 점검 루트 아래 실제 일반 파일이면 그 파일의 ctime(메타데이터 변경 — 생성·chmod·
  chown·이동). ctime은 `touch -t`로 안 바뀌어 mtime보다 정직하다. mtime은 다르면 보조로 함께 표시

시간 원칙: 순서와 표시에만 쓰고 위험도는 바꾸지 않는다. 미래 시각은 조작 의심으로 표시(LOG-06 교차).
시계를 통째로 돌리면 ctime도 속으므로, 타임라인은 증거가 아니라 단서다 — 머리말에 경고.
"""
import stat

from . import timefmt
from .checks.base import Unavailable

GROUP_GAP = 300          # 5분 이내 사건은 한 '활동 구간'
# /proc·/sys는 가상 파일시스템이라 ctime이 디스크 흔적의 시각이 아니다 (프로세스 시작 시각 등) — 제외
PSEUDO = ("/proc/", "/sys/")
WARNING = ("시각은 조작될 수 있습니다(touch, 시스템 시계 변경). 이 순서는 사건을 좁히는 단서일 뿐 "
           "그 자체로 증거가 아닙니다.")
SEV_RANK = {"critical": 0, "warning": 1, "info": 2}


class Event:
    __slots__ = ("time", "future", "severity", "check_id", "title", "detail", "kind")

    def __init__(self, time, future, severity, check_id, title, detail, kind):
        self.time = time
        self.future = future
        self.severity = severity
        self.check_id = check_id
        self.title = title
        self.detail = detail
        self.kind = kind        # 사건(로그·로그인) / 파일(ctime)

    def to_dict(self):
        return {"time_str": timefmt.absolute(self.time), "future": self.future, "severity": self.severity,
                "check_id": self.check_id, "title": self.title, "detail": self.detail, "kind": self.kind}


def _reg_times(ctx, path):
    """일반 파일의 (ctime, mtime). 일반 파일이 아니거나 못 읽으면 None."""
    try:
        st = ctx.stat(path, follow=False)
    except Unavailable:
        return None
    if st is None or not stat.S_ISREG(st.st_mode):
        return None
    return st.st_ctime, st.st_mtime


def events(ctx, findings, extra_files=None):
    """[Event], 시각을 못 구한 탐지 [(check_id, title, severity)]."""
    evs, unknown, seen = [], [], set()
    for f in findings:
        produced = False
        if f.timestamp:
            _, fut = timefmt.describe(f.timestamp, ctx.now)
            key = (f.check_id, "t", round(f.timestamp))
            if key not in seen:
                seen.add(key)
                evs.append(Event(f.timestamp, fut, f.severity, f.check_id, f.title,
                                 (f.reason or "")[:140], "사건"))
            produced = True
        done_paths = set()
        for e in f.evidence:
            src = e.source
            if not src or not src.startswith("/") or src.startswith(PSEUDO) or src in done_paths:
                continue
            t = _reg_times(ctx, src)
            if t is None:
                continue
            done_paths.add(src)
            ctime, mtime = t
            key = (f.check_id, src, round(ctime))
            if key in seen:
                produced = True
                continue
            seen.add(key)
            _, fut = timefmt.describe(ctime, ctx.now)
            detail = "{} 메타데이터 변경(ctime)".format(src)
            if abs(mtime - ctime) > 1:
                mfut = (ctx.now - mtime) < -timefmt.FUTURE_TOLERANCE
                detail += " · 내용(mtime) {}{}".format(timefmt.absolute(mtime), " ⚠미래" if mfut else "")
            evs.append(Event(ctime, fut, f.severity, f.check_id, f.title, detail, "파일"))
            produced = True
        if not produced:
            unknown.append((f.check_id, f.title, f.severity))
    for path, label in (extra_files or []):
        t = _reg_times(ctx, path)
        if t is None:
            continue
        ctime, _ = t
        key = ("BASELINE", path, round(ctime))
        if key in seen:
            continue
        seen.add(key)
        _, fut = timefmt.describe(ctime, ctx.now)
        evs.append(Event(ctime, fut, "warning", "기준선", label,
                         "{} 메타데이터 변경(ctime)".format(path), "파일"))
    evs.sort(key=lambda e: (e.time, SEV_RANK.get(e.severity, 9), e.check_id))
    return evs, unknown


def build_block(ctx, findings, extra_files=None):
    """리포트에 실을 타임라인 사전. 시각 있는 사건이 2개 미만이면 None."""
    evs, unknown = events(ctx, findings, extra_files)
    if len(evs) < 2:
        return None
    groups, cur = [], None
    for e in evs:
        if cur is None or e.time - cur[-1].time > GROUP_GAP:
            cur = [e]
            groups.append(cur)
        else:
            cur.append(e)
    group_dicts = []
    for g in groups:
        start, end = g[0].time, g[-1].time
        span = timefmt.span(end - start) if end > start else "한때"
        group_dicts.append({
            "start_str": timefmt.absolute(start), "end_str": timefmt.absolute(end),
            "span_str": span, "future": any(e.future for e in g),
            "events": [e.to_dict() for e in g]})
    seen_unknown, unknown_out = set(), []
    for cid, title, sev in unknown:
        if cid in seen_unknown:
            continue
        seen_unknown.add(cid)
        unknown_out.append({"check_id": cid, "title": title, "severity": sev})
    return {
        "warning": WARNING,
        "counts": {"events": len(evs), "groups": len(group_dicts), "unknown": len(unknown_out)},
        "groups": group_dicts,
        "unknown": unknown_out,
    }
