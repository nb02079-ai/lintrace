"""커널 NFS 서비스(nfsd·lockd)가 연 소켓의 포트.

nfsd·lockd는 커널 안에서 소켓을 연다. 이 소켓들은 inode는 있지만 어느 프로세스의 파일 설명자에도 없어서,
'주인 없는 리스닝 소켓'(NET-01)과 겉모습이 같다 (lin.security 정답, 2026-11-06). 커널이 직접 알려 주는
값과 맞대어 가린다.

- nfsd: /proc/fs/nfsd/portlist ('tcp 2049' — IPv4·IPv6 소켓이 한 줄씩)
- lockd: /proc/sys/fs/nfs/nlm_tcpport·nlm_udpport (0이면 부팅마다 바뀌는 동적 포트)
- 동적 포트는 rpcbind 등록으로만 알 수 있다: 'rpcinfo'(옵션 없이 — '-p'는 IPv4만 보여줌)의 프로그램
  100021(nlockmgr)·100003(nfs)·100227(nfs_acl), 소유자 superuser. 주소는 universal address로 끝 두 숫자가
  포트의 상위·하위 바이트다 ('0.0.0.0.149.119' = 38263, '::.135.79' = 34639).

사용법: info = kernel_nfs(ctx) — 같은 Context에서는 저장된 결과를 돌려준다.
"""
import shutil
import subprocess

from ..checks.base import Unavailable

PROGRAMS = {"100021": "lockd", "100003": "nfsd", "100227": "nfsd"}
NETIDS = ("tcp", "udp", "tcp6", "udp6")


class KernelNfs:
    def __init__(self):
        self.nfsd = False       # 모듈이 올라와 있는지
        self.lockd = False
        self.ports = {}         # (프로토콜, 포트) → 'nfsd' / 'lockd'
        self.rpc_ok = None      # rpcinfo를 읽었는지 (None: 필요 없어 안 읽음)

    @property
    def active(self):
        return self.nfsd or self.lockd

    def add(self, proto, port, who):
        """'tcp' → tcp·tcp6 둘 다 (portlist·nlm 포트는 IPv4·IPv6 구분이 없다)."""
        for p in ((proto, proto + "6") if not proto.endswith("6") else (proto,)):
            self.ports.setdefault((p, port), who)

    def owner(self, sock):
        return self.ports.get((sock.proto, sock.local[1])) if sock.local else None


def parse_portlist(lines, info):
    for line in lines:
        f = line.split()
        if len(f) == 2 and f[0] in ("tcp", "udp") and f[1].isdigit():
            info.add(f[0], int(f[1]), "nfsd")


def parse_rpcinfo(text, info):
    """'rpcinfo' 출력: program version netid address service owner."""
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] not in PROGRAMS or f[2] not in NETIDS or f[5] != "superuser":
            continue
        parts = f[3].rsplit(".", 2)
        if len(parts) != 3 or not (parts[1].isdigit() and parts[2].isdigit()):
            continue
        hi, lo = int(parts[1]), int(parts[2])
        if hi > 255 or lo > 255:
            continue
        info.ports.setdefault((f[2], hi * 256 + lo), PROGRAMS[f[0]])


def run_rpcinfo():
    """rpcbind 등록 목록 (읽기만 하는 명령). 없거나 실패하면 None."""
    exe = shutil.which("rpcinfo")
    if not exe:
        return None
    try:
        r = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def read_lines(ctx, path):
    try:
        return ctx.read_lines(path, missing_ok=True)
    except Unavailable:
        return []


def kernel_nfs(ctx, rpcinfo=None):
    """rpcinfo: rpcbind 등록 목록을 돌려주는 함수 (테스트에서 바꿔 끼운다). 없으면 실제 시스템에서만 실행."""
    cached = getattr(ctx, "_kernel_nfs", None)
    if cached is not None:
        return cached
    info = KernelNfs()
    info.nfsd = ctx.exists("/sys/module/nfsd")
    info.lockd = ctx.exists("/sys/module/lockd")
    if info.active:
        parse_portlist(read_lines(ctx, "/proc/fs/nfsd/portlist"), info)
        for proto in ("tcp", "udp"):
            lines = read_lines(ctx, "/proc/sys/fs/nfs/nlm_{}port".format(proto))
            if lines and lines[0].strip().isdigit() and int(lines[0]) > 0:
                info.add(proto, int(lines[0]), "lockd")
        if rpcinfo is None:
            # rpcbind는 실제 시스템에만 물을 수 있다 (--root로 다른 디스크를 볼 때는 엉뚱한 답)
            rpcinfo = run_rpcinfo if ctx.root == "/" else (lambda: None)
        text = rpcinfo()
        info.rpc_ok = text is not None
        if text:
            parse_rpcinfo(text, info)
    ctx._kernel_nfs = info
    return info
