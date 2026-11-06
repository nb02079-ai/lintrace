"""스크립트·명령 내용의 의심 패턴 (PER-01에서 꺼내 PER-03·04·06·08·09가 함께 쓴다).

판정
- 심각: 내려받아 바로 실행 / 리버스 셸 / 인코딩을 풀어 실행 / 임시 폴더의 파일 실행
- 위험: 시스템 영역의 숨김 경로에 있는 파일 실행

알려진 한계: 셸 문법을 완전히 해석하지 않는다. 변수로 만든 명령(`$CMD`)은 판단하지 못한다.
"""
import posixpath
import re

ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
CD = re.compile(r"(?:^|[\s;&|(])cd\s+([^\s;&|)]+)")
MAX_SCRIPT_BYTES = 1024 * 1024

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


def scan_command(command):
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
    return found


def scan_lines(lines):
    """스크립트 여러 줄. 주석 줄은 건너뛴다. [(위험도, 설명, 줄 번호, 줄)]"""
    out = []
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        for sev, why in scan_command(s):
            out.append((sev, why, no, s))
    return out
