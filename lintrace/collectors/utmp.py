"""wtmp·btmp 로그인 기록 해석 (LOG-02).

/var/log/wtmp(성공한 로그인·부팅), /var/log/btmp(실패한 로그인)는 utmp 구조체(리눅스 x86-64에서 384바이트)의
배열이다. 공격자는 자기 로그인 줄을 지우거나 파일을 비운다.

구조체에서 쓰는 것: ut_type(종류), ut_user(32바이트), ut_line(터미널 32바이트), ut_host(256바이트),
ut_tv(시각 — 초·마이크로초 4바이트씩). 종류 7=사용자 로그인, 8=로그아웃, 2=부팅.

사용법: w = wtmp(ctx), b = btmp(ctx)
"""
import struct

RECORD = 384
# ut_type(short) ut_pid(int) ut_line[32] ut_id[4] ut_user[32] ut_host[256] ... ut_tv(int,int) ...
# 앞부분만 고정으로 떼고, 시각은 구조체 끝 근처라 오프셋으로 읽는다
HEAD = struct.Struct("<h2xi32s4s32s256s")  # type,(pad),pid,line,id,user,host = 2+2+4+32+4+32+256 = 332
TV_OFFSET = 340  # ut_session(int) 뒤의 ut_tv.tv_sec
LOGIN, LOGOUT, BOOT, RUN_LVL = 7, 8, 2, 1


class Login:
    __slots__ = ("type", "user", "line", "host", "ts")

    def __init__(self, t, user, line, host, ts):
        self.type, self.user, self.line, self.host, self.ts = t, user, line, host, ts


def _s(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def parse(data):
    out, ok = [], (len(data) % RECORD == 0)
    for i in range(0, len(data) - RECORD + 1, RECORD):
        rec = data[i:i + RECORD]
        t, pid, line, uid, user, host = HEAD.unpack(rec[:HEAD.size])
        tv_sec = struct.unpack_from("<i", rec, TV_OFFSET)[0]
        out.append(Login(t, _s(user), _s(line), _s(host), tv_sec))
    return out, ok


class Utmp:
    def __init__(self, path, present, logins, aligned, size):
        self.path = path
        self.present = present      # 파일이 있는지
        self.logins = logins
        self.aligned = aligned      # 크기가 레코드 배수인지
        self.size = size

    def user_logins(self):
        return [l for l in self.logins if l.type == LOGIN and l.user]

    def begins(self):
        times = [l.ts for l in self.logins if l.ts > 0]
        return min(times) if times else None


def _read(ctx, path):
    st = ctx.stat(path, follow=True)
    if st is None:
        return Utmp(path, False, [], True, 0)
    data = ctx.read_head(path, 20 * 1024 * 1024)
    logins, aligned = parse(data)
    return Utmp(path, True, logins, aligned, st.st_size)


def wtmp(ctx):
    cached = getattr(ctx, "_wtmp", None)
    if cached is None:
        cached = ctx._wtmp = _read(ctx, "/var/log/wtmp")
    return cached


def btmp(ctx):
    cached = getattr(ctx, "_btmp", None)
    if cached is None:
        cached = ctx._btmp = _read(ctx, "/var/log/btmp")
    return cached
