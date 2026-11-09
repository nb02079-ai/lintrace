"""인증 로그 수집기.

/var/log/auth.log와 순환 파일(.1, .N.gz)을 오래된 순서로 이어 읽어 줄마다
(시각, 호스트, 프로그램, PID, 메시지)로 나눈다. ACC-02·03·08·09가 함께 쓴다.

- 시각 형식 두 가지: 18.04 'Nov  3 03:02:25' (연도가 없어 점검 시각의 연도로 보고, 미래가 되면 한 해 전)
  / 24.04 '2026-11-03T01:37:19.443184+00:00'
- 로그 중간에 NUL(0) 바이트가 섞여 있어도 (스냅샷 복원·비정상 종료) 건너뛰고 끝까지 읽는다.
- 이 수집기는 판정에 쓸 사건의 순서와 간격을 얻으려는 것이다 (파일 변경 시각은 쓰지 않는다).

사용법: log = auth_log(ctx) — log.available이 False면 인증 로그가 없다 (journal은 2-E에서 읽는다).
"""
import datetime
import gzip
import os
import re
import stat
import time

from ..checks.base import Unavailable

LOG = "/var/log/auth.log"
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                                      "Sep", "Oct", "Nov", "Dec"], start=1)}
ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?\s+(\S+)\s+(.*)$")
BSD = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+(.*)$")
PROG = re.compile(r"^([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$")
SSHD = ("sshd", "sshd-session")
MAX_BYTES = 512 * 1024 * 1024


class Entry:
    __slots__ = ("ts", "host", "prog", "pid", "msg", "source", "lineno", "raw")

    def __init__(self, ts, host, prog, pid, msg, source, lineno, raw):
        self.ts, self.host, self.prog, self.pid, self.msg = ts, host, prog, pid, msg
        self.source, self.lineno, self.raw = source, lineno, raw

    def where(self):
        return "{}행".format(self.lineno)


def parse_line(line, now, source="", lineno=0):
    """한 줄 → Entry. 형식을 모르면 None."""
    m = ISO.match(line)
    if m:
        y, mo, d, h, mi, s, tz, host, rest = m.groups()
        try:
            dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
        except ValueError:
            return None
        if tz:
            if tz == "Z":
                offset = 0
            else:
                sign = -1 if tz[0] == "-" else 1
                hh, mm = tz[1:3], tz[-2:]
                offset = sign * (int(hh) * 3600 + int(mm) * 60)
            ts = (dt - datetime.datetime(1970, 1, 1)).total_seconds() - offset
        else:
            ts = time.mktime(dt.timetuple())
    else:
        m = BSD.match(line)
        if not m:
            return None
        mon, d, h, mi, s, host, rest = m.groups()
        if mon not in MONTHS:
            return None
        year = time.localtime(now).tm_year
        try:
            ts = time.mktime((year, MONTHS[mon], int(d), int(h), int(mi), int(s), 0, 0, -1))
            if ts > now + 86400:  # 연도가 없는 형식: 미래가 되면 작년 기록이다
                ts = time.mktime((year - 1, MONTHS[mon], int(d), int(h), int(mi), int(s), 0, 0, -1))
        except (OverflowError, ValueError):
            return None
    p = PROG.match(rest)
    if not p:
        return None
    return Entry(ts, host, p.group(1), p.group(2), p.group(3), source, lineno, line)


class AuthLog:
    def __init__(self, entries, files, lines, available):
        self.entries = entries      # 오래된 순서
        self.files = files          # 읽은 파일 경로
        self.lines = lines          # 읽은 줄 수 (형식을 모르는 줄 포함)
        self.available = available

    def sshd(self):
        return [e for e in self.entries if e.prog in SSHD]

    def scope(self):
        if not self.available:
            return "인증 로그 없음 (journal은 2-E에서)"
        extra = getattr(self, "journal_added", 0)
        if not self.files:
            return "인증 로그 파일 없음, journal sshd 기록 {:,}건".format(extra)
        return "인증 로그 파일 {}개·{:,}줄{}".format(
            len(self.files), self.lines, ", journal 보충 {:,}건".format(extra) if extra else "")


def log_files(ctx):
    """오래된 것부터: auth.log.N.gz … auth.log.2.gz, auth.log.1, auth.log"""
    directory, base = os.path.split(LOG)
    numbered = []
    for name in ctx.list_dir(directory):
        m = re.match(re.escape(base) + r"\.(\d+)(\.gz)?$", name)
        if m:
            numbered.append((int(m.group(1)), name))
    out = [os.path.join(directory, n) for _, n in sorted(numbered, reverse=True)]
    if ctx.stat(LOG, follow=True) is not None:
        out.append(LOG)
    return out


def read_bytes(ctx, path):
    full = ctx.path(path)
    try:
        st = os.stat(full)
        if not stat.S_ISREG(st.st_mode):
            return b""
        if path.endswith(".gz"):
            with gzip.open(full, "rb") as f:
                return f.read(MAX_BYTES)
        with open(full, "rb") as f:
            return f.read(MAX_BYTES)
    except PermissionError:
        raise Unavailable("{} 읽기 권한 없음 (root로 실행 필요)".format(path))
    except (OSError, EOFError):
        return b""  # 깨진 gz 등은 건너뛴다


def auth_log(ctx):
    cached = getattr(ctx, "_auth_log", None)
    if cached is not None:
        return cached
    files = log_files(ctx)
    entries, lines = [], 0
    for path in files:
        data = read_bytes(ctx, path)
        for no, raw in enumerate(data.split(b"\n"), start=1):
            raw = raw.replace(b"\0", b"")  # 스냅샷 복원·비정상 종료로 생긴 NUL 구간
            if not raw.strip():
                continue
            lines += 1
            line = raw.decode("utf-8", "replace").rstrip("\r")
            e = parse_line(line, ctx.now, path, no)
            if e:
                entries.append(e)
    from_journal = _journal_sshd(ctx, entries)
    entries += from_journal
    entries.sort(key=lambda e: e.ts)
    log = AuthLog(entries, files, lines, bool(files) or bool(from_journal))
    log.journal_added = len(from_journal)
    ctx._auth_log = log
    return log


def _journal_sshd(ctx, file_entries):
    """auth.log에 없는 sshd 기록을 journal에서 가져온다 (인증 로그가 없거나 비어 있을 때 보충).

    같은 사건이 auth.log와 journal 양쪽에 있을 수 있어, (초 단위 시각, 메시지)로 중복을 뺀다.
    """
    from .journal import journal
    j = journal(ctx)
    if not j.available:
        return []
    have = {(int(e.ts), e.msg) for e in file_entries}
    out = []
    for r in j.of_prog(SSHD):
        key = (int(r.realtime), r.msg)
        if key in have:
            continue
        have.add(key)
        out.append(Entry(r.realtime, "", r.prog, None, r.msg, "journal", 0, r.msg))
    return out
