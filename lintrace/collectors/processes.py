"""프로세스 수집기.

/proc를 한 번만 훑어 모든 프로세스 정보를 모으고 Context에 보관한다.
PRC 계열 항목은 이 표를 함께 쓴다. 항목마다 /proc를 다시 읽으면 그사이 프로세스가
생기거나 끝나 항목끼리 결과가 엇갈릴 수 있기 때문이다.

사용법: table = processes(ctx) — 같은 Context에서는 두 번째부터 저장된 표를 돌려준다.
열린 파일 목록(/proc/<pid>/fd)은 쓰는 항목이 있을 때 table.open_files(ctx)로 한 번만 읽는다.
"""
import os

from .. import timefmt
from ..checks.base import Evidence, Unavailable

DELETED = " (deleted)"
MAX_LISTED = 10


def clock_ticks():
    try:
        return os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        return 100


class Proc:
    """프로세스 하나. exe는 /proc/<pid>/exe 링크 문자열 그대로 (커널 스레드는 None)."""

    def __init__(self, pid):
        self.pid = pid
        self.exe = None
        self.name = "?"
        self.ppid = "?"
        self.uid = "?"
        self.user = "?"
        self.argv = []
        self.cmdline = ""
        self.parent = "?"
        self.cwd = None
        self.started = None

    @property
    def deleted(self):
        return bool(self.exe) and self.exe.endswith(DELETED)

    @property
    def exe_path(self):
        """'(deleted)'를 뗀 실행 파일 경로."""
        if not self.exe:
            return None
        return self.exe[:-len(DELETED)] if self.deleted else self.exe

    @property
    def memfd(self):
        return bool(self.exe) and self.exe.startswith("/memfd:")


class ProcessTable:
    def __init__(self, procs, denied, total):
        self.procs = procs      # 실행 파일 정보를 읽은 프로세스 [Proc]
        self.denied = denied    # 접근 거부된 PID [str]
        self.total = total      # /proc에 있던 프로세스 수
        self._files = None
        self.fd_denied = []     # fd 목록을 읽지 못한 PID

    def open_files(self, ctx):
        """프로세스가 연 파일 [(Proc, fd 번호, 링크 대상)]. 처음 부를 때 한 번만 읽고 저장한다."""
        if self._files is None:
            files = []
            for p in self.procs:
                base = "/proc/{}/fd".format(p.pid)
                try:
                    fds = ctx.list_dir(base)
                except Unavailable:
                    self.fd_denied.append(p.pid)
                    continue
                for fd in sorted(fds, key=lambda x: int(x) if x.isdigit() else -1):
                    target = ctx.readlink(base + "/" + fd)
                    if target:
                        files.append((p, fd, target))
            self._files = files
        return self._files

    def require_access(self):
        """root가 아니라서 남의 프로세스를 못 봤으면 부분 결과를 정상처럼 내지 않는다."""
        if self.denied and os.geteuid() != 0:
            raise Unavailable("프로세스 {}개의 실행 파일 정보를 읽을 권한 없음 (root로 실행 필요)".format(len(self.denied)))

    def scope(self, ctx):
        """점검 범위 문장. root로도 접근 거부된 프로세스(도구보다 커널 권한이 큰 프로세스 등)는 밝힌다."""
        text = "프로세스 {}개".format(self.total - len(self.denied))
        if self.denied:
            names = []
            for pid in self.denied[:MAX_LISTED]:
                comm = ctx.read_lines("/proc/{}/comm".format(pid), missing_ok=True)
                names.append("PID {} {}".format(pid, comm[0] if comm else "?"))
            more = " 외 {}개".format(len(self.denied) - MAX_LISTED) if len(self.denied) > MAX_LISTED else ""
            text += "(root로도 접근 거부된 {}개 제외: {}{})".format(len(self.denied), ", ".join(names), more)
        return text


def processes(ctx):
    cached = getattr(ctx, "_process_table", None)
    if cached is None:
        cached = _collect(ctx)
        ctx._process_table = cached
    return cached


def _collect(ctx):
    pids = sorted((n for n in ctx.list_dir("/proc") if n.isdigit()), key=int)
    users = {}
    for line in ctx.read_lines("/etc/passwd", missing_ok=True):
        parts = line.split(":")
        if len(parts) >= 3:
            users.setdefault(parts[2], parts[0])
    boot_time = None
    for line in ctx.read_lines("/proc/stat", missing_ok=True):
        if line.startswith("btime "):
            boot_time = int(line.split()[1])
    own = str(os.getpid()) if ctx.root == "/" else None

    procs, denied = [], []
    for pid in pids:
        if pid == own:
            continue
        try:
            exe = ctx.readlink("/proc/{}/exe".format(pid), strict=True)
        except Unavailable:  # 권한 없음 — 남의 프로세스, 또는 도구보다 권한이 큰 프로세스
            denied.append(pid)
            continue
        if exe is None:
            continue  # 커널 스레드이거나 그사이 끝난 프로세스
        p = Proc(pid)
        p.exe = exe
        _fill(ctx, p, users, boot_time)
        procs.append(p)
    return ProcessTable(procs, denied, len(pids))


def _fill(ctx, p, users, boot_time):
    base = "/proc/{}".format(p.pid)
    status = {}
    for line in ctx.read_lines(base + "/status", missing_ok=True):
        if ":" in line:
            k, v = line.split(":", 1)
            status[k] = v.strip()
    p.name = status.get("Name", "?")
    p.ppid = status.get("PPid", "?")
    if status.get("Uid"):
        p.uid = status["Uid"].split()[0]
    p.user = "{}({})".format(users.get(p.uid, "?"), p.uid)
    raw = ctx.read_head(base + "/cmdline", 4096)
    p.argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
    p.cmdline = " ".join(p.argv) or "[{}]".format(p.name)
    if p.ppid not in ("?", "0"):
        comm = ctx.read_lines("/proc/{}/comm".format(p.ppid), missing_ok=True)
        p.parent = comm[0] if comm else "?"
    p.cwd = ctx.readlink(base + "/cwd")
    stat_line = ctx.read_lines(base + "/stat", missing_ok=True)
    if stat_line and boot_time is not None:
        # 2번째 필드(이름)에 공백·괄호가 들어갈 수 있어 마지막 ')' 뒤에서 센다
        fields = stat_line[0].rsplit(")", 1)[-1].split()
        if len(fields) > 19 and fields[19].isdigit():
            p.started = boot_time + int(fields[19]) / clock_ticks()


def describe(p, now):
    """근거 한 줄: PID, 계정, 시작 경과, 부모, 명령줄."""
    started = ("시작 " + timefmt.describe(p.started, now)[0]) if p.started else "시작 시각 모름"
    return "PID {}, 계정 {}, {}, 부모 PID {}({}): {}".format(p.pid, p.user, started, p.ppid, p.parent, p.cmdline)


def evidence_for(ctx, procs):
    """프로세스 묶음의 근거. 많으면 앞의 몇 개만 자세히 보이고 나머지는 PID만."""
    out = [Evidence("/proc/{}".format(p.pid), describe(p, ctx.now)) for p in procs[:MAX_LISTED]]
    if len(procs) > MAX_LISTED:
        out.append(Evidence("/proc", "외 {}개 프로세스: PID {}".format(
            len(procs) - MAX_LISTED, ", ".join(p.pid for p in procs[MAX_LISTED:]))))
    return out
