"""소켓 수집기.

/proc/net의 tcp·tcp6·udp·udp6·raw·raw6·packet·unix 목록을 읽고, 프로세스가 연 파일의
'socket:[inode]'와 이어 어느 프로세스가 어느 소켓을 잡고 있는지 만든다 (PRC-06·08, NET-01·02).

inode가 0인 소켓은 커널이 직접 연 것이다 (NFS 서버의 nfsd·lockd 등) — 소유 프로세스가 없는 게 정상.

사용법: table = sockets(ctx) — 같은 Context에서는 저장된 표를 돌려준다.
"""
import socket
import struct

from .processes import processes

INET = ("tcp", "tcp6", "udp", "udp6", "raw", "raw6")
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
LOOPBACK = ("127.",)


def parse_addr(text, v6):
    """'0100007F:0016' → ('127.0.0.1', 22). /proc/net은 32비트 단위로 호스트 바이트 순서(리틀 엔디언)."""
    host, port = text.split(":")
    raw = bytes.fromhex(host)
    if v6:
        raw = b"".join(struct.pack(">I", struct.unpack("<I", raw[i:i + 4])[0]) for i in range(0, 16, 4))
        if raw[:12] == b"\0" * 10 + b"\xff\xff":   # IPv4-mapped (::ffff:a.b.c.d)
            ip = socket.inet_ntop(socket.AF_INET, raw[12:])
        else:
            ip = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        ip = socket.inet_ntop(socket.AF_INET, struct.pack(">I", struct.unpack("<I", raw)[0]))
    return ip, int(port, 16)


class Sock:
    __slots__ = ("proto", "local", "remote", "state", "uid", "inode", "iface", "path", "owners")

    def __init__(self, proto, local=None, remote=None, state=None, uid=None, inode="0", iface=None, path=None):
        self.proto, self.local, self.remote, self.state = proto, local, remote, state
        self.uid, self.inode, self.iface, self.path = uid, inode, iface, path
        self.owners = []    # [(Proc, fd)]

    @property
    def listening(self):
        if self.proto in ("tcp", "tcp6"):
            return self.state == "LISTEN"
        if self.proto in ("udp", "udp6"):
            return self.remote is not None and self.remote[1] == 0
        return False

    @property
    def established(self):
        return self.proto in ("tcp", "tcp6") and self.state == "ESTABLISHED"

    @property
    def kernel(self):
        return self.inode == "0"

    def describe(self):
        if self.proto == "packet":
            return "packet 소켓 (프로토콜 0x{}, 인터페이스 {})".format(self.state, self.iface)
        if self.proto == "unix":
            return "unix 소켓 {}".format(self.path or "(이름 없음)")
        left = "{}:{}".format(*self.local) if self.local else "?"
        if self.listening or self.proto.startswith("raw"):
            return "{} {}".format(self.proto, left)
        right = "{}:{}".format(*self.remote) if self.remote else "?"
        return "{} {} → {} ({})".format(self.proto, left, right, self.state)


class SocketTable:
    def __init__(self, socks):
        self.socks = socks
        self.by_inode = {}
        for s in socks:
            if not s.kernel:
                self.by_inode.setdefault(s.inode, s)

    def of(self, proto_prefixes):
        return [s for s in self.socks if s.proto.startswith(proto_prefixes)]


def read_inet(ctx, name):
    out = []
    v6 = name.endswith("6")
    for line in ctx.read_lines("/proc/net/" + name, missing_ok=True)[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            local, remote = parse_addr(f[1], v6), parse_addr(f[2], v6)
        except (ValueError, OSError, struct.error):
            continue
        state = TCP_STATES.get(f[3].upper(), f[3]) if name.startswith("tcp") else f[3]
        out.append(Sock(name, local, remote, state, f[7], f[9]))
    return out


def read_packet(ctx):
    out = []
    for line in ctx.read_lines("/proc/net/packet", missing_ok=True)[1:]:
        f = line.split()
        if len(f) >= 9:
            out.append(Sock("packet", state=f[3], iface=f[4], uid=f[7], inode=f[8]))
    return out


def read_unix(ctx):
    out = []
    for line in ctx.read_lines("/proc/net/unix", missing_ok=True)[1:]:
        f = line.split()
        if len(f) >= 7:
            out.append(Sock("unix", inode=f[6], path=f[7] if len(f) > 7 else None))
    return out


def sockets(ctx):
    cached = getattr(ctx, "_socket_table", None)
    if cached is not None:
        return cached
    socks = []
    for name in INET:
        socks += read_inet(ctx, name)
    socks += read_packet(ctx) + read_unix(ctx)
    table = SocketTable(socks)
    for p, fd, target in processes(ctx).open_files(ctx):
        if target.startswith("socket:[") and target.endswith("]"):
            s = table.by_inode.get(target[8:-1])
            if s is not None:
                s.owners.append((p, fd))
    ctx._socket_table = table
    return table


def is_loopback(ip):
    return ip.startswith(LOOPBACK) or ip == "::1"
