"""셸 명령 기록 수집기 (CMD-01·02, 2-E의 LOG-03).

모든 사용자 홈(/etc/passwd의 홈 중 실제로 있는 폴더, /root 포함)의 명령 기록 파일을 읽는다.
- bash·sh·ash: 한 줄에 명령 하나. HISTTIMEFORMAT을 쓰면 '#1699999999' 줄이 다음 명령의 시각
- zsh 확장 형식: ': 1699999999:0;명령'
- fish: '- cmd: 명령' 다음 줄 '  when: 1699999999'
명령 기록 안의 시각은 사건 순서를 보는 데만 쓴다 (파일 변경 시각과 달리 시간 원칙에 걸리지 않음).

사용법: h = history(ctx) — 같은 Context에서는 저장된 결과를 돌려준다.
"""
import posixpath
import re

FILES = [".bash_history", ".zsh_history", ".history", ".sh_history", ".ash_history", ".mksh_history",
         ".local/share/fish/fish_history"]
BASH_TS = re.compile(r"^#(\d{9,11})\s*$")
ZSH = re.compile(r"^: (\d{9,11}):\d+;(.*)$")
FISH_CMD = re.compile(r"^- cmd: (.*)$")
FISH_WHEN = re.compile(r"^\s+when: (\d{9,11})\s*$")
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/nonexistent")


class Entry:
    __slots__ = ("user", "path", "lineno", "ts", "cmd")

    def __init__(self, user, path, lineno, ts, cmd):
        self.user, self.path, self.lineno, self.ts, self.cmd = user, path, lineno, ts, cmd


class History:
    def __init__(self):
        self.files = []        # [(사용자, 경로, 명령 수, 로그인 셸 없는 계정인지)]
        self.entries = []      # [Entry]

    def of(self, path):
        return [e for e in self.entries if e.path == path]


def parse(lines, user, path):
    out, ts = [], None
    fish = path.endswith("fish_history")
    for no, raw in enumerate(lines, start=1):
        if fish:
            m = FISH_CMD.match(raw)
            if m:
                out.append(Entry(user, path, no, None, m.group(1)))
                continue
            m = FISH_WHEN.match(raw)
            if m and out:
                out[-1].ts = int(m.group(1))
            continue
        m = BASH_TS.match(raw)
        if m:
            ts = int(m.group(1))
            continue
        m = ZSH.match(raw)
        if m:
            out.append(Entry(user, path, no, int(m.group(1)), m.group(2)))
            ts = None
            continue
        if raw.strip():
            out.append(Entry(user, path, no, ts, raw))
        ts = None
    return out


def accounts(ctx):
    """[(사용자, 홈, 셸)] — 홈이 실제로 있는 계정 (홈 중복 제거)."""
    out, seen = [], set()
    for line in ctx.read_lines("/etc/passwd", missing_ok=True):
        parts = line.split(":")
        if len(parts) < 7 or not parts[5].startswith("/") or parts[5] in ("/", "/nonexistent"):
            continue
        home = parts[5].rstrip("/")
        if home in seen or ctx.stat(home, follow=True) is None:
            continue
        seen.add(home)
        out.append((parts[0], home, parts[6].strip()))
    return out


def history(ctx):
    cached = getattr(ctx, "_history", None)
    if cached is not None:
        return cached
    h = History()
    for user, home, shell in accounts(ctx):
        for name in FILES:
            path = posixpath.join(home, name)
            st = ctx.stat(path)
            if st is None or not (st.st_mode & 0o170000 == 0o100000):
                continue  # 없거나 일반 파일이 아님 (/dev/null 링크는 LOG-03이 본다)
            entries = parse(ctx.read_lines(path), user, path)
            h.files.append((user, path, len(entries), shell in NOLOGIN or shell.endswith("nologin")))
            h.entries += entries
    ctx._history = h
    return h
