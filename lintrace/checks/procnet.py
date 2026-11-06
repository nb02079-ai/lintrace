"""PRC·NET 항목이 함께 쓰는 '수상한 프로세스' 판단.

포트 번호나 IP로 정상 여부를 가리려면 그 서버의 평소 상태(기준선)가 필요하다. 기준선 비교는 3단계에서
만들고, 그 전까지는 '누가 리스닝·연결하는가'로 본다 (2026-11-06 결정).
"""
import posixpath

from ..collectors.packages import packages
from .prc_01 import odd_location
from .prc_03 import interpreter_name

NET_TOOLS = {"nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "cryptcat", "pwncat"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"}


def exe_name(p):
    return posixpath.basename(p.exe_path or "")


def suspicious(ctx, p):
    """수상한 이유 목록 (없으면 빈 목록)."""
    why = []
    name = exe_name(p)
    interp = interpreter_name(p)
    if p.memfd:
        why.append("디스크에 없는 실행 파일(memfd)")
    elif p.deleted:
        why.append("지워진 실행 파일")
    if interp in SHELLS:
        why.append("셸({})".format(name or interp))
    elif interp:
        why.append("인터프리터({})".format(name or interp))
    if name in NET_TOOLS:
        why.append("네트워크 도구({})".format(name))
    if p.exe_path and not p.memfd:
        where = odd_location(p.exe_path)
        if where:
            why.append("실행 파일이 {}에 있음".format(where))
        db = packages(ctx)
        if db.available and not p.deleted and db.owner(p.exe_path) is None:
            why.append("실행 파일이 패키지에 속하지 않음")
    return why
