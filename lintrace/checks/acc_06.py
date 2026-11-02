"""ACC-06 sudo로 root 셸을 얻을 수 있는 권한 부여.

/etc/sudoers와 그 안에서 불러오는 파일(@includedir, @include)을 읽어, 일반 사용자가
root 권한으로 셸이나 셸 탈출이 되는 프로그램을 실행할 수 있게 허용한 규칙을 찾는다.
NOPASSWD 여부는 탐지 조건이 아니라 위험도를 올리는 조건으로만 쓴다.
(lin.security처럼 비밀번호를 묻지만 bash를 허용한 경우를 놓치지 않기 위해서다.)

판정
- 심각: 명령 전체(ALL)나 셸 자체를 허용, 또는 위험 프로그램을 NOPASSWD로 허용
- 위험: 셸 탈출이 되는 프로그램이나 인자 제한 없는 파일 쓰기 프로그램을 허용
- 제외: root, %sudo, %admin, %wheel 같은 기본 관리자 규칙

알려진 한계 (발견하면 fixture와 함께 확장할 것)
- 한 줄에 호스트 지정이 여럿인 규칙(`u h1 = cmd : h2 = cmd`)은 첫 지정만 본다.
- 호스트 조건은 보지 않는다 (모든 호스트에 적용된다고 가정).
- 인자를 고정한 셸 탈출 프로그램(예: `/usr/bin/less /var/log/syslog`)도 탈출이
  가능한 경우가 많아 그대로 탐지한다. 실제 악용 가능 여부는 분석가가 확인한다.
- Defaults 설정(env_keep의 LD_PRELOAD 등)으로 생기는 권한 상승은 다루지 않는다.
"""
import posixpath
import re

from .base import Check, Context, Evidence

# 출처: GTFOBins (https://gtfobins.github.io/) 중 'Sudo' 기능이 있는 프로그램
SHELLS = {"sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish"}
ESCAPE = {
    "awk", "gawk", "mawk", "nawk", "busybox", "ed", "ex", "vi", "vim", "rvim", "view",
    "rview", "vimdiff", "nano", "pico", "emacs", "less", "more", "man", "find", "xargs",
    "perl", "python", "ruby", "irb", "lua", "php", "node", "tclsh", "wish", "expect",
    "env", "git", "script", "ftp", "ssh", "scp", "socat", "nmap", "tar", "zip", "rsync",
    "gdb", "strace", "docker", "journalctl", "systemctl", "crontab", "apt", "apt-get",
    "dpkg", "sed", "tmux", "screen", "make", "nice", "timeout", "time", "watch", "flock",
    "sqlite3", "mysql", "su", "sudo",
}
# 인자 제한이 없으면 /etc/sudoers나 /etc/shadow를 덮어써 root를 얻을 수 있는 프로그램
FILE_WRITE = {"curl", "wget", "cp", "mv", "tee", "dd", "install", "chmod", "chown", "ln"}

ADMIN_USERS = {"root", "%sudo", "%admin", "%wheel"}
TAGS = {
    "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT",
    "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOW", "NOFOLLOW",
    "INTERCEPT", "NOINTERCEPT",
}

DIRECTIVE = re.compile(r"^[#@](includedir|include)\s+(\S+)")
ALIAS_LINE = re.compile(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)\s+(.*)$")
ALIAS_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
RUNAS = re.compile(r"^\(([^)]*)\)\s*")
TAG = re.compile(r"^([A-Z_]+)\s*:\s*")
DIGEST = re.compile(r"^(sha224|sha256|sha384|sha512):")
MAX_DEPTH = 8


def logical_lines(lines):
    """줄 끝의 '\\'로 이어진 줄을 합친다. (시작 줄 번호, 합친 줄)을 돌려준다."""
    buf, start = "", None
    for no, raw in enumerate(lines, start=1):
        if start is None:
            start = no
        if raw.endswith("\\") and not raw.endswith("\\\\"):
            buf += raw[:-1] + " "
            continue
        yield start, buf + raw
        buf, start = "", None
    if start is not None:
        yield start, buf


def strip_comment(line):
    """'#' 뒤를 지운다. 단 '#1000' 같은 UID 표기와 '\\#'는 주석이 아니다."""
    out, i = [], 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            out.append(line[i:i + 2])
            i += 2
            continue
        if c == "#" and not (i + 1 < len(line) and line[i + 1].isdigit()):
            break
        out.append(c)
        i += 1
    return "".join(out).strip()


def split_top(s, sep):
    """괄호 밖, 이스케이프되지 않은 sep에서만 나눈다. '(root, bob)' 안의 쉼표는 그대로 둔다."""
    parts, buf, depth, i = [], [], 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i:i + 2])
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def classify(cmd):
    """명령 하나를 (분류, 표시 이름)으로 나눈다. 위험하지 않으면 (None, None)."""
    parts = [p for p in cmd.split() if not DIGEST.match(p)]
    if not parts:
        return None, None
    prog, args = parts[0], parts[1:]
    if prog == "ALL":
        return "all", "ALL"
    if "*" in prog:  # 예: /usr/bin/* — 경로 와일드카드는 사실상 명령 전체
        return "all", prog
    base = posixpath.basename(prog)
    # vim.basic → vim, python3.6 → python, tclsh8.6 → tclsh
    norm = re.sub(r"\d+$", "", base.split(".")[0])
    if base in SHELLS or norm in SHELLS:
        return "shell", base
    if base in ESCAPE or norm in ESCAPE:
        return "escape", base
    if norm in FILE_WRITE and (not args or any("*" in a for a in args)):
        return "write", base
    return None, None


class _Sudoers:
    """sudoers 파일들을 읽어 별칭과 사용자 규칙을 모은다."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.aliases = {"User_Alias": {}, "Runas_Alias": {}, "Cmnd_Alias": {}}
        self.alias_src = {}  # (종류, 이름) → (파일 경로, 줄 번호, 정의 줄) — 근거 표시용
        self.rules = []      # (파일 경로, 줄 번호, 규칙 줄)
        self.visited = set()

    def parse_file(self, path, depth=0, missing_ok=False):
        if depth > MAX_DEPTH or path in self.visited:
            return
        self.visited.add(path)
        for no, line in logical_lines(self.ctx.read_lines(path, missing_ok=missing_ok)):
            s = line.strip()
            m = DIRECTIVE.match(s)  # '#includedir'은 '#'로 시작하지만 주석이 아니다
            if m:
                kind, target = m.groups()
                if not target.startswith("/"):
                    target = posixpath.join(posixpath.dirname(path), target)
                if kind == "includedir":
                    for name in self.ctx.list_dir(target):
                        # sudo 규칙: '~'로 끝나거나 '.'이 들어간 파일은 읽지 않는다
                        if name.endswith("~") or "." in name:
                            continue
                        self.parse_file(posixpath.join(target, name), depth + 1, missing_ok=True)
                else:
                    self.parse_file(target, depth + 1, missing_ok=True)
                continue
            s = strip_comment(s)
            if not s or s.startswith("Defaults"):
                continue
            m = ALIAS_LINE.match(s)
            if m:
                kind = "Cmnd_Alias" if m.group(1) == "Cmd_Alias" else m.group(1)
                for part in split_top(m.group(2), ":"):
                    if "=" not in part or kind not in self.aliases:
                        continue
                    name, value = part.split("=", 1)
                    name = name.strip()
                    self.aliases[kind][name] = [v.strip() for v in split_top(value, ",") if v.strip()]
                    self.alias_src[(kind, name)] = (path, no, s)
                continue
            if "=" in s:
                self.rules.append((path, no, s))

    def expand(self, kind, items, used, depth=0):
        """별칭을 풀어 쓴다. 풀어 쓴 별칭은 used에 (종류, 이름)으로 기록한다."""
        out = []
        for it in items:
            it = it.strip()
            if not it:
                continue
            if depth < MAX_DEPTH and ALIAS_NAME.match(it) and it in self.aliases[kind]:
                used.add((kind, it))
                out.extend(self.expand(kind, self.aliases[kind][it], used, depth + 1))
            else:
                out.append(it)
        return out

    def runs_as_root(self, spec, used):
        """'(ALL)', '(ALL:ALL)', '(root)', '(:wheel)' 등에서 root로 실행되는지 본다."""
        user_part = spec.split(":", 1)[0]
        if not user_part.strip():
            return False  # '(:그룹)'만 있으면 실행하는 본인 계정으로 돈다
        users = self.expand("Runas_Alias", user_part.split(","), used)
        return any(u in ("ALL", "root", "#0") for u in users)

    def alias_lines(self, used):
        """사용된 별칭의 정의 줄을 (파일, 줄 번호, 내용)으로, 중복 없이 순서대로 돌려준다."""
        lines = {self.alias_src[key] for key in used if key in self.alias_src}
        return sorted(lines, key=lambda x: (x[0], x[1]))

    def analyze(self, text):
        """규칙 한 줄을 분석한다. 위험하지 않으면 None.

        돌려주는 값: (사용자 목록, 분류별 프로그램, NOPASSWD 여부, 사용된 별칭)
        """
        used = set()
        left, right = text.split("=", 1)
        tokens = re.sub(r"\s*,\s*", ",", left.strip()).split()
        if len(tokens) < 2:
            return None
        users = [u for u in self.expand("User_Alias", tokens[0].split(","), used) if not u.startswith("!")]
        risky_users = [u for u in users if u not in ADMIN_USERS]
        if not risky_users:
            return None

        hits = {"all": set(), "shell": set(), "escape": set(), "write": set()}
        as_root, nopasswd, nopasswd_hit = True, False, False  # runas를 안 쓰면 root가 기본
        for item in split_top(right, ","):
            item = item.strip()
            m = RUNAS.match(item)
            if m:  # runas와 태그는 같은 줄의 뒤쪽 명령에도 이어서 적용된다
                as_root = self.runs_as_root(m.group(1), used)
                item = item[m.end():]
            while True:
                m = TAG.match(item)
                if not m or m.group(1) not in TAGS:
                    break
                if m.group(1) == "NOPASSWD":
                    nopasswd = True
                elif m.group(1) == "PASSWD":
                    nopasswd = False
                item = item[m.end():]
            if not item or item.startswith("!") or not as_root:
                continue
            for cmd in self.expand("Cmnd_Alias", [item], used):
                if cmd.startswith("!"):
                    continue
                category, name = classify(cmd)
                if category:
                    hits[category].add(name)
                    nopasswd_hit = nopasswd_hit or nopasswd
        if not any(hits.values()):
            return None
        return risky_users, hits, nopasswd_hit, used


class Acc06(Check):
    id = "ACC-06"
    title = "sudo로 root 셸을 얻을 수 있는 권한 부여"
    severity = "warning"
    attack = "T1548.003"

    def run(self, ctx: Context):
        if ctx.stat("/etc/sudoers") is None:
            return []  # sudo가 설치되지 않은 시스템 (못 보는 경우는 stat이 Unavailable을 낸다)
        sudoers = _Sudoers(ctx)
        sudoers.parse_file("/etc/sudoers")

        findings = []
        for path, no, text in sudoers.rules:
            result = sudoers.analyze(text)
            if result is None:
                continue
            users, hits, nopasswd, used = result
            if hits["all"] or hits["shell"] or nopasswd:
                severity = "critical"
            else:
                severity = "warning"
            groups = []
            for key, label in (("all", "명령 전체"), ("shell", "셸"),
                               ("escape", "셸 탈출"), ("write", "파일 쓰기")):
                if hits[key]:
                    names = sorted(hits[key])
                    groups.append("{} {}개({})".format(label, len(names), ", ".join(names)))
            reason = "'{}' 계정이 root 권한으로 실행할 수 있다: {}".format(
                ", ".join(users), " / ".join(groups))
            if nopasswd:
                reason += " — 비밀번호 없이(NOPASSWD) 실행 가능"
            findings.append(self.finding(
                reason=reason,
                next_steps="이 권한이 업무에 필요한지 확인하고, 규칙이 추가된 시점(파일 변경 시각)과 "
                           "해당 계정의 sudo 사용 기록(auth.log의 'COMMAND=')을 확인한다.",
                # 규칙 줄 + 그 규칙이 쓴 별칭의 정의 줄 (별칭을 찾으러 sudoers를 다시 열 필요가 없게)
                evidence=[Evidence(path, "{}행: {}".format(no, text))] + [
                    Evidence(p, "{}행 (별칭 정의): {}".format(n, t))
                    for p, n, t in sudoers.alias_lines(used)],
                severity=severity,
            ))
        return findings
