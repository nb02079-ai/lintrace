"""PRC-01 실행 파일이 삭제된 채 도는 프로세스.

공격자는 악성 프로그램을 실행한 뒤 파일을 지워 흔적을 없앤다. 프로세스는 계속 돌고
/proc/<PID>/exe가 '<원래 경로> (deleted)'를 가리킨다. 지워진 파일도 /proc/<PID>/exe로
읽을 수 있으므로 SHA-256을 계산해 근거에 남긴다 (읽기만 하고 복사하지 않는다).

판정
- 심각: 원래 위치가 임시 폴더·숨김 경로
- 심각: 지워진 경로에 지금 아무 파일도 없음
- 참고: 같은 경로에 지금 파일이 있음 — 패키지 업데이트 후 재시작하지 않은 서비스에서 흔함.
        바꿔치기와 구분할 수 있게 실행 중인 파일과 디스크 파일의 해시를 함께 보인다.
- 제외: memfd 실행(파일 없는 실행, PRC-02가 맡음), 커널 스레드(실행 파일 없음)

같은 실행 파일로 도는 프로세스(워커 등)는 한 건으로 묶는다.
"""
import os

from .. import timefmt
from .base import Check, Context, Evidence, Unavailable

DELETED = " (deleted)"
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
MAX_LISTED = 10


def odd_location(path):
    if path.startswith(TEMP_DIRS):
        return "임시 폴더"
    if any(p.startswith(".") and p not in (".", "..") for p in path.split("/") if p):
        return "숨김 경로"
    return None


def clock_ticks():
    try:
        return os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        return 100


class _Proc:
    """프로세스 하나의 정보를 /proc에서 읽는다. 사라진 프로세스면 값이 비어 있다."""

    def __init__(self, ctx, pid, users, boot_time):
        base = "/proc/{}".format(pid)
        self.pid = pid
        status = {}
        for line in ctx.read_lines(base + "/status", missing_ok=True):
            if ":" in line:
                k, v = line.split(":", 1)
                status[k] = v.strip()
        self.name = status.get("Name", "?")
        self.ppid = status.get("PPid", "?")
        uid = status.get("Uid", "?").split()[0] if status.get("Uid") else "?"
        self.user = "{}({})".format(users.get(uid, "?"), uid)
        raw = ctx.read_head(base + "/cmdline", 4096)
        self.cmdline = raw.replace(b"\0", b" ").decode("utf-8", "replace").strip() or "[{}]".format(self.name)
        self.parent = "?"
        if self.ppid not in ("?", "0"):
            comm = ctx.read_lines("/proc/{}/comm".format(self.ppid), missing_ok=True)
            self.parent = comm[0] if comm else "?"
        self.started = None
        stat_line = ctx.read_lines(base + "/stat", missing_ok=True)
        if stat_line and boot_time is not None:
            # 2번째 필드(이름)에 공백·괄호가 들어갈 수 있어 마지막 ')' 뒤에서 센다
            fields = stat_line[0].rsplit(")", 1)[-1].split()
            if len(fields) > 19 and fields[19].isdigit():
                self.started = boot_time + int(fields[19]) / clock_ticks()


class Prc01(Check):
    id = "PRC-01"
    title = "실행 파일이 삭제된 채 도는 프로세스"
    severity = "critical"
    attack = "T1070.004"

    def run(self, ctx: Context):
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

        groups = {}       # 지워진 경로 → [PID]
        denied = []
        own = str(os.getpid()) if ctx.root == "/" else None
        for pid in pids:
            try:
                exe = ctx.readlink("/proc/{}/exe".format(pid), strict=True)
            except Unavailable:  # 권한 없음 — 남의 프로세스, 또는 도구보다 권한이 큰 프로세스
                denied.append(pid)
                continue
            if exe is None or pid == own:
                continue  # 커널 스레드이거나 그사이 끝난 프로세스
            if not exe.endswith(DELETED):
                continue
            path = exe[:-len(DELETED)]
            if path.startswith("/memfd:") or not path.startswith("/"):
                continue  # 파일 없는 실행은 PRC-02가 본다
            groups.setdefault(path, []).append(pid)

        if denied and os.geteuid() != 0:
            # root가 아니면 남의 프로세스를 거의 다 못 본다 — 부분 결과를 정상처럼 내지 않는다
            raise Unavailable("프로세스 {}개의 실행 파일 정보를 읽을 권한 없음 (root로 실행 필요)".format(len(denied)))

        findings = [self.report(ctx, path, groups[path], users, boot_time) for path in sorted(groups)]
        self.scope = "프로세스 {}개".format(len(pids) - len(denied))
        if denied:
            # root로도 거부되는 프로세스(도구보다 커널 권한이 큰 프로세스 등)는 이름과 함께 밝힌다
            names = []
            for pid in denied[:MAX_LISTED]:
                comm = ctx.read_lines("/proc/{}/comm".format(pid), missing_ok=True)
                names.append("PID {} {}".format(pid, comm[0] if comm else "?"))
            more = " 외 {}개".format(len(denied) - MAX_LISTED) if len(denied) > MAX_LISTED else ""
            self.scope += "(root로도 접근 거부된 {}개 제외: {}{})".format(len(denied), ", ".join(names), more)
        return findings

    def report(self, ctx, path, pids, users, boot_time):
        now_file = ctx.stat(path, follow=True)
        where = odd_location(path)
        running_hash = ctx.sha256("/proc/{}/exe".format(pids[0]))

        if where:
            severity = "critical"
            reason = "실행 파일이 지워진 채 도는 프로세스 {}개: 원래 위치 {}가 {}에 있다".format(len(pids), path, where)
        elif now_file is None:
            severity = "critical"
            reason = "실행 파일이 지워진 채 도는 프로세스 {}개: {}에 지금 아무 파일도 없다".format(len(pids), path)
        else:
            severity = "info"
            reason = ("실행 파일이 바뀐 뒤 재시작하지 않은 프로세스 {}개: {} (패키지 업데이트 후 흔함 — "
                      "아래 두 해시가 같은 패키지 버전인지 확인)".format(len(pids), path))

        evidence = []
        for pid in pids[:MAX_LISTED]:
            p = _Proc(ctx, pid, users, boot_time)
            started = ("시작 " + timefmt.describe(p.started, ctx.now)[0]) if p.started else "시작 시각 모름"
            evidence.append(Evidence("/proc/{}".format(pid), "PID {}, 계정 {}, {}, 부모 PID {}({}): {}".format(
                pid, p.user, started, p.ppid, p.parent, p.cmdline)))
        if len(pids) > MAX_LISTED:
            evidence.append(Evidence("/proc", "외 {}개 프로세스: PID {}".format(
                len(pids) - MAX_LISTED, ", ".join(pids[MAX_LISTED:]))))
        evidence.append(Evidence("/proc/{}/exe".format(pids[0]),
                                 "실행 중인 파일 SHA-256: {}".format(running_hash or "계산 불가")))
        if now_file is not None:
            evidence.append(Evidence(path, "지금 디스크에 있는 파일 SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))

        if severity == "critical":
            steps = ("SHA-256으로 악성코드 데이터베이스를 조회하고, 프로세스를 끝내기 전에 /proc/<PID>/exe를 "
                     "복사해 증거로 보존한다. 네트워크 연결(ss -p)과 부모 프로세스를 확인한다.")
        else:
            steps = ("두 해시가 다르면 'apt list --upgradable' 기록이나 dpkg 로그로 업데이트 여부를 확인하고, "
                     "정상 업데이트면 서비스를 재시작한다. 업데이트 기록이 없으면 바꿔치기를 의심한다.")
        return self.finding(reason=reason, next_steps=steps, evidence=evidence, severity=severity)
