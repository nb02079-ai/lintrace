"""PER-01 crontab의 의심 명령.

cron이 실행하는 모든 예약 작업과, root 작업이 실행하는 스크립트까지 따라가서
명령 내용을 점검한다. 시간 원칙에 따라 언제 바뀌었는지는 위험도에 쓰지 않는다.

읽는 곳
- /etc/crontab, /etc/cron.d/* (사용자 필드 있음)
- /var/spool/cron/crontabs/* (사용자별 crontab, 파일 이름 = 사용자)
- /etc/anacrontab (root)
- root 작업이 실행하는 스크립트: 명령에 나오는 절대 경로 스크립트,
  run-parts 대상 폴더(/etc/cron.daily 등)의 스크립트

판정
- 심각: 내려받아 바로 실행 / 리버스 셸 / 인코딩을 풀어 실행 / 임시 폴더의 파일 실행
- 심각: root 작업의 tar·rsync 와일드카드가 사용자가 쓸 수 있는 폴더에서 풀림 (옵션 주입)
- 위험: 풀리는 위치를 판단할 수 없는 tar·rsync 와일드카드 (root 작업)
- 위험: root가 실행하는 파일이나 그 폴더를 다른 사용자가 쓸 수 있음
- 위험: 시스템 영역의 숨김 경로에 있는 파일 실행 (/usr/.x/y 등. 홈의 .local 같은 경로는 제외)
- 참고: @reboot 작업, 일반 사용자의 crontab

알려진 한계
- 스크립트는 한 단계만 따라간다 (스크립트가 부르는 다른 스크립트는 읽지 않음).
- 셸 문법을 완전히 해석하지 않는다. 변수로 만든 명령(`$CMD`)은 판단하지 못한다.
- 와일드카드가 풀리는 위치는 같은 줄의 cd 대상, 스크립트의 앞선 cd, '*' 앞 경로로만 추정한다.
"""
import posixpath
import re
import stat

from .. import timefmt
from .base import Check, Context, Evidence

SYSTEM_TABS = ["/etc/crontab"]
CRON_D = "/etc/cron.d"
USER_SPOOL = "/var/spool/cron/crontabs"
ANACRONTAB = "/etc/anacrontab"
STANDARD_RUN_PARTS = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]

# cron(Debian)과 run-parts가 읽는 파일 이름 규칙. '.'이 들어간 파일(.placeholder, *.dpkg-old)은 무시된다.
VALID_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
SPECIALS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
MAX_SCRIPT_BYTES = 1024 * 1024
USER_WRITABLE_DIRS = ("/home", "/tmp", "/var/tmp", "/dev/shm")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")

SHELL = r"(?:ba|da|z|k)?sh\b"
DOWNLOAD_EXEC = [
    re.compile(r"\b(?:curl|wget)\b[^;&|]*\|\s*(?:sudo\s+)?" + SHELL),
    re.compile(SHELL + r"\s+(?:-c\s+)?[\"']?\$\(\s*(?:curl|wget)\b"),
    re.compile(r"<\(\s*(?:curl|wget)\b"),
]
REVERSE_SHELL = [
    re.compile(r"/dev/(?:tcp|udp)/"),
    re.compile(r"\bn(?:c|cat|etcat)\b[^;&|]*\s(?:-[a-z]*[ec]\b|--(?:sh-)?exec\b)"),
    re.compile(r"\bsocat\b[^;&|]*\bexec:", re.I),
    re.compile(r"\bmkfifo\b[^\n]*\bn(?:c|cat)\b"),
    re.compile(r"\b(?:python[\d.]*|perl|ruby|php)\b[^;&|]*\s-[a-z]*[ce]\b[^\n]*\bsocket\b"),
]
B64_EXEC = [
    re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^;&]*\|\s*(?:sudo\s+)?" + SHELL),
    re.compile(r"\beval\b[^;]*\bbase64\s+(?:-d|--decode|-D)\b"),
]
# 명령 자리를 나누는 구분자 ($( 와 셸 예약어 포함)
SEGMENT = re.compile(r"&&|\|\||\$\(|[;|&(){}`]|\b(?:then|do|else)\b")
WRAPPERS = {"sudo", "nohup", "exec", "nice", "ionice", "timeout", "env", "command", "time", "flock"}
INTERPRETER = re.compile(r"^(?:(?:ba|da|z|k)?sh|python[\d.]*|perl|php[\d.]*|ruby|node)$")
WILDCARD_CMD = re.compile(r"(?:^|[\s/;&|(])(tar|rsync)\b([^;&|]*)")
CD = re.compile(r"(?:^|[\s;&|(])cd\s+([^\s;&|)]+)")
RUN_PARTS = re.compile(r"\brun-parts\b(?:\s+-{1,2}[\w-]+(?:=\S+)?)*\s+(/[^\s;&|)]+)")


SH_C_PAYLOAD = re.compile(r"\b(?:ba|da|z|k)?sh\s+-c\s+'([^']*)'")
SINGLE_QUOTED = re.compile(r"'[^']*'")


def exec_paths(command, depth=0):
    """명령 자리에 오는 실행 파일을 뽑는다. 'sh /x.sh'처럼 인터프리터 뒤의 스크립트도 포함.

    작은따옴표 안은 바깥 셸이 실행하지 않으므로 지우고 본다. 단 sh -c '...' 안의
    명령은 실제로 실행되므로 따로 꺼내 같은 방식으로 본다.
    """
    out = []
    if depth < 3:
        for payload in SH_C_PAYLOAD.findall(command):
            out += exec_paths(payload, depth + 1)
    for seg in SEGMENT.split(SINGLE_QUOTED.sub("''", command)):
        toks = seg.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if ENV_LINE.match(t):          # FOO=1 cmd
                i += 1
            elif t in WRAPPERS:            # sudo / timeout 10 / nice -n 5 ...
                i += 1
                while i < len(toks) and (toks[i].startswith("-") or toks[i][:1].isdigit()):
                    i += 1
            else:
                break
        if i >= len(toks):
            continue
        prog = toks[i].strip("\"'")
        if not prog:
            continue
        if INTERPRETER.match(posixpath.basename(prog)):
            j = i + 1
            while j < len(toks) and toks[j].startswith("-"):
                if toks[j] in ("-c", "-e"):  # 문자열 코드 실행 — 파일이 아님
                    j = len(toks)
                    break
                j += 1
            if j < len(toks):
                out.append(toks[j].strip("\"'"))
            continue
        out.append(prog)
    return out


def hidden_system_path(path):
    """시스템 영역 안의 숨김 경로인지 본다. 홈(/home, /root) 아래의 .local 등은 정상으로 본다."""
    if not path.startswith("/"):
        return False
    parts = [p for p in path.split("/") if p]
    if not parts or parts[0] in ("home", "root"):
        return False
    return any(p.startswith(".") and p not in (".", "..") for p in parts[:-1]) or parts[-1].startswith("...")


def wildcard_hits(line, cwd):
    """root 작업 줄에서 tar·rsync 와일드카드를 찾는다. [(명령, 인자, 풀리는 위치 또는 None)]"""
    hits = []
    cds = CD.findall(line)
    where = cds[0] if cds else cwd
    for m in WILDCARD_CMD.finditer(line):
        for tok in m.group(2).split():
            if "*" not in tok or tok.startswith("-") or tok[:1] in "\"'":
                continue
            base = tok if tok.startswith("/") else where
            hits.append((m.group(1), tok, base))
    return hits


def in_user_writable(path):
    return bool(path) and any(path == d or path.startswith(d + "/") for d in USER_WRITABLE_DIRS)


class _Job:
    def __init__(self, src, no, line, user, special, command):
        self.src, self.no, self.line = src, no, line
        self.user, self.special, self.command = user, special, command


def parse_tab(lines, src, has_user_field, owner=None):
    """crontab 형식 파일을 작업 목록으로 바꾼다."""
    jobs = []
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#") or ENV_LINE.match(s):
            continue
        if s.startswith("@"):
            parts = s.split(None, 2 if has_user_field else 1)
            if parts[0] not in SPECIALS or len(parts) < (3 if has_user_field else 2):
                continue
            special = parts[0]
        else:
            parts = s.split(None, 6 if has_user_field else 5)
            if len(parts) < (7 if has_user_field else 6):
                continue
            parts = ["schedule"] + parts[5:]
            special = None
        user = parts[1] if has_user_field else owner
        jobs.append(_Job(src, no, s, user, special, parts[-1]))
    return jobs


def parse_anacrontab(lines, src):
    jobs = []
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#") or ENV_LINE.match(s):
            continue
        parts = s.split(None, 3)
        if len(parts) == 4 and (parts[0].isdigit() or parts[0].startswith("@")):
            jobs.append(_Job(src, no, s, "root", None, parts[3]))
    return jobs


def command_conditions(command, root, cwd=None):
    """명령 한 줄의 의심 조건. [(위험도, 설명)]"""
    found = []
    if any(p.search(command) for p in DOWNLOAD_EXEC):
        found.append(("critical", "내려받아 바로 실행한다 (curl/wget → 셸)"))
    if any(p.search(command) for p in REVERSE_SHELL):
        found.append(("critical", "리버스 셸 형태의 명령이다"))
    if any(p.search(command) for p in B64_EXEC):
        found.append(("critical", "인코딩된 내용을 풀어 실행한다 (base64 → 셸)"))
    paths = exec_paths(command)
    temp = [p for p in paths if p.startswith(TEMP_DIRS)]
    cds = CD.findall(command)
    if not temp and any(c.rstrip("/") + "/" in TEMP_DIRS for c in cds) and \
            any(p.startswith("./") for p in paths):
        temp = ["{}/{}".format(cds[0].rstrip("/"), p[2:]) for p in paths if p.startswith("./")]
    if temp:
        found.append(("critical", "임시 폴더의 파일을 실행한다: {}".format(", ".join(temp))))
    hidden = [p for p in paths if hidden_system_path(p) and not p.startswith(TEMP_DIRS)]
    if hidden:
        found.append(("warning", "시스템 영역의 숨김 경로에 있는 파일을 실행한다: {}".format(", ".join(hidden))))
    if root:
        for cmd, tok, where in wildcard_hits(command, cwd):
            if in_user_writable(where):
                found.append(("critical", "root 작업의 {} 인자 '{}'가 사용자가 쓸 수 있는 폴더({})에서 풀린다 — "
                                          "'-'로 시작하는 파일 이름으로 옵션을 주입해 root 권한을 얻을 수 있다"
                              .format(cmd, tok, where)))
            else:
                found.append(("warning", "root 작업의 {} 인자 '{}'에 와일드카드가 있다 (풀리는 위치 확인 필요)"
                              .format(cmd, tok)))
    return found


class Per01(Check):
    id = "PER-01"
    title = "crontab의 의심 명령"
    severity = "critical"
    attack = "T1053.003"

    def run(self, ctx: Context):
        root_users = {"root"}
        for line in ctx.read_lines("/etc/passwd", missing_ok=True):
            parts = line.split(":")
            if len(parts) >= 7 and parts[2] == "0":
                root_users.add(parts[0])

        jobs = []
        for tab in SYSTEM_TABS:
            jobs += parse_tab(ctx.read_lines(tab, missing_ok=True), tab, True)
        for name in ctx.list_dir(CRON_D):
            if VALID_NAME.match(name):
                path = posixpath.join(CRON_D, name)
                if self.regular(ctx, path):
                    jobs += parse_tab(ctx.read_lines(path), path, True)
        user_tabs = []
        for name in ctx.list_dir(USER_SPOOL):
            path = posixpath.join(USER_SPOOL, name)
            if not name.startswith(".") and self.regular(ctx, path):
                user_jobs = parse_tab(ctx.read_lines(path), path, False, owner=name)
                jobs += user_jobs
                if name not in root_users and user_jobs:
                    user_tabs.append((path, name, len(user_jobs)))
        jobs += parse_anacrontab(ctx.read_lines(ANACRONTAB, missing_ok=True), ANACRONTAB)

        findings = []
        # root가 실행하는 스크립트 → 실행하는 곳 목록
        scripts = {}
        for job in jobs:
            root = job.user in root_users
            conditions = command_conditions(job.command, root)
            if root:
                for d in RUN_PARTS.findall(job.command):
                    self.add_run_parts(ctx, scripts, d, Evidence(job.src, "{}행 (실행하는 곳): {}".format(job.no, job.line)))
                for p in exec_paths(job.command):
                    if not p.startswith("/"):
                        continue
                    if self.is_script(ctx, p):
                        # 스크립트의 쓰기 권한은 scan_script()에서 한 번만 본다 (중복 경고 방지)
                        scripts.setdefault(posixpath.normpath(p), []).append(
                            Evidence(job.src, "{}행 (실행하는 곳): {}".format(job.no, job.line)))
                    else:
                        conditions += self.writable_conditions(ctx, p)
            if job.special == "@reboot" and not conditions:
                conditions.append(("info", "@reboot — 부팅할 때마다 실행된다"))
            if conditions:
                findings.append(self.make(ctx, "'{}' 권한으로 실행되는 예약 작업".format(job.user),
                                          job.src, job.no, job.line, conditions, []))

        for d in STANDARD_RUN_PARTS:  # crontab에서 참조하지 않아도 anacron이 실행할 수 있다
            self.add_run_parts(ctx, scripts, d, Evidence(d, "run-parts 표준 대상 폴더"), only_if_new=True)

        for path in sorted(scripts):
            findings += self.scan_script(ctx, path, scripts[path])

        for path, user, count in user_tabs:
            when, _ = timefmt.describe(ctx.stat(path).st_mtime, ctx.now)
            findings.append(self.finding(
                reason="'{}' 계정의 crontab에 예약 작업 {}개가 있다.".format(user, count),
                next_steps="이 계정이 예약 작업을 쓸 이유가 있는지 확인하고, 각 작업이 실행하는 파일을 확인한다.",
                evidence=[Evidence(path, "작업 {}개".format(count)), Evidence(path, "파일 변경: {}".format(when))],
                severity="info",
            ))

        self.scope = "예약 작업 {}개, root가 실행하는 스크립트 {}개".format(len(jobs), len(scripts))
        return findings

    # --- 도우미 ---

    @staticmethod
    def regular(ctx, path):
        st = ctx.stat(path, follow=True)
        return st is not None and stat.S_ISREG(st.st_mode)

    @staticmethod
    def is_script(ctx, path):
        st = ctx.stat(path, follow=True)
        return (st is not None and stat.S_ISREG(st.st_mode) and st.st_size <= MAX_SCRIPT_BYTES
                and ctx.read_head(path, 2) == b"#!")

    def add_run_parts(self, ctx, scripts, directory, runner, only_if_new=False):
        for name in ctx.list_dir(directory):
            path = posixpath.join(directory, name)
            st = ctx.stat(path, follow=True)
            # run-parts는 이름 규칙에 맞는 실행 가능한 일반 파일만 실행한다
            if not VALID_NAME.match(name) or st is None or not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
                continue
            if only_if_new and path in scripts:
                continue
            if self.is_script(ctx, path):
                scripts.setdefault(path, []).append(runner)
            else:
                scripts.setdefault(path, [])

    @staticmethod
    def writable_conditions(ctx, path):
        """root가 실행하는 파일을 다른 사용자가 바꿀 수 있는지 본다."""
        found = []
        st = ctx.stat(path, follow=True)
        if st is None or not stat.S_ISREG(st.st_mode):
            return found
        if st.st_mode & 0o022 or st.st_uid != 0:
            found.append(("warning", "root가 실행하는 {}를 다른 사용자가 바꿀 수 있다 (권한 {:o}, 소유자 UID {})"
                          .format(path, stat.S_IMODE(st.st_mode), st.st_uid)))
        parent = posixpath.dirname(path)
        dst = ctx.stat(parent, follow=True)
        if dst is not None and dst.st_mode & 0o022 and not dst.st_mode & stat.S_ISVTX:
            found.append(("warning", "root가 실행하는 파일이 있는 {}를 다른 사용자가 쓸 수 있다 (권한 {:o})"
                          .format(parent, stat.S_IMODE(dst.st_mode))))
        return found

    def scan_script(self, ctx, path, runners):
        findings = []
        writable = self.writable_conditions(ctx, path)
        if writable:
            findings.append(self.make(ctx, "root가 실행하는 스크립트 {}".format(path), path, None, None,
                                      writable, runners))
        if not self.is_script(ctx, path):
            return findings  # 바이너리는 내용을 읽지 않는다
        cwd = None
        for no, raw in enumerate(ctx.read_lines(path), start=1):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            conditions = command_conditions(s, True, cwd)
            cds = CD.findall(s)
            if cds:
                cwd = cds[-1]
            if conditions:
                findings.append(self.make(ctx, "root가 실행하는 스크립트 {}".format(path), path, no, s,
                                          conditions, runners))
        return findings

    def make(self, ctx, subject, src, no, line, conditions, runners):
        rank = {"critical": 0, "warning": 1, "info": 2}
        severity = min((c[0] for c in conditions), key=rank.get)
        evidence = []
        if line is not None:
            evidence.append(Evidence(src, "{}행: {}".format(no, line)))
        evidence += runners
        st = ctx.stat(src, follow=True)
        if st is not None:
            evidence.append(Evidence(src, "파일 변경: {}".format(timefmt.describe(st.st_mtime, ctx.now)[0])))
        steps = "이 작업을 누가 추가했는지 확인하고(파일 변경 시각, 패키지 소속), 명령이 실행하는 파일과 접속 주소를 조사한다."
        if any("옵션을 주입" in c[1] for c in conditions):
            steps = ("와일드카드가 풀리는 폴더에 '-'로 시작하는 이름의 파일(예: --checkpoint-action=exec=...)이 "
                     "있는지 확인하고, 'tar ... -- *' 또는 'tar ... ./*'처럼 고쳐 파일 이름이 옵션으로 "
                     "해석되지 않게 한다.")
        return self.finding(
            reason="{}: {}".format(subject, "; ".join(c[1] for c in conditions)),
            next_steps=steps,
            evidence=evidence,
            severity=severity,
        )
