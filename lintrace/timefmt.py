"""경과 시간 표시.

시간 원칙: 파일 변경 시각은 `touch` 한 번으로 조작되므로 위험도 판단에 쓰지 않고
근거에 경과 시간으로만 보여준다. 예외로 현재보다 미래인 시각은 조작 흔적으로 본다.
"""
import time

# 시계 오차로 몇 초 앞선 정도는 미래 시각으로 보지 않는다
FUTURE_TOLERANCE = 60


def span(seconds):
    """초를 사람이 읽는 기간으로 바꾼다 (예: '3일', '약 8년')."""
    s = int(seconds)
    if s < 60:
        return "{}초".format(s)
    if s < 3600:
        return "{}분".format(s // 60)
    if s < 86400:
        return "{}시간".format(s // 3600)
    days = s // 86400
    if days < 30:
        return "{}일".format(days)
    if days < 365:
        return "약 {}개월".format(days // 30)
    return "약 {}년".format(days // 365)


def absolute(ts):
    """점검 대상 시스템의 시간대로 찍은 절대 시각."""
    return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(ts))


def describe(ts, now):
    """(표시 문자열, 미래 시각 여부)를 돌려준다.

    예: ('3일 전 (2026-10-30 14:02:11 +0900)', False)
    """
    diff = now - ts
    if diff < -FUTURE_TOLERANCE:
        return "현재보다 {} 뒤 — 미래 시각 ({})".format(span(-diff), absolute(ts)), True
    return "{} 전 ({})".format(span(max(diff, 0)), absolute(ts)), False
