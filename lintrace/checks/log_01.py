"""LOG-01 로그 파일이 비었거나 잘림.

공격자는 침입 흔적을 지우려고 로그에서 자기 줄을 지우거나(sed -i, 편집기 저장),
파일을 비우거나(: > auth.log), 통째로 지운다(rm). 로그를 쓰는 프로세스(rsyslogd, nginx 등)는
파일을 연 채로 쓰기 때문에, 경로의 파일이 바뀌거나 지워져도 원래 파일을 계속 붙잡고 있고
/proc/<pid>/fd 링크가 '<경로> (deleted)'로 바뀐다. 이 차이로 바꿔치기를 찾는다.

대상
- rsyslog 설정(/etc/rsyslog.conf와 그 Include)이 기록하는 파일: 시설 규칙 줄, 필터 줄
  (:msg,contains,…), 비동기 표시(-/var/log/…), action(type="omfile" file="…")
- nginx(access_log·error_log)와 Apache(CustomLog·ErrorLog) 로그
- 지워진 채 열린 검사는 /var/log 아래 파일을 연 모든 프로세스 (journal은 LOG-04·05가 본다)

판정
- 심각: 프로세스가 현재 로그 이름의 파일을 지워진 채 붙잡고 있음 (내용 바꿔 다시 저장, 또는 삭제)
- 심각: 로그 앞부분이 NUL(0 바이트)로 채워짐 — 쓰는 중인 파일을 비우면 다음 기록이 예전 위치에 써진다
- 위험: 계속 기록되는 로그(인증·전체 로그, 웹 access 로그)가 비어 있음 — 순환 직후에도 생길 수 있음
        (sudo로 실행했으면 auth.log에 방금 기록이 남았어야 하지만, 'sudo -i' 셸 안에서 실행하면
         그 기록이 순환 전 파일에 있을 수 있어 심각으로 올리지 않는다 — 2026-11-03 결정)
- 위험: 순환 사슬이 끊김 (.2.gz는 있는데 .1이 없음), 또는 현재 파일 없이 순환 파일만 있음

정상으로 보는 것
- 설정에 있지만 아직 없는 파일 (rsyslog는 첫 메시지가 올 때 만든다)
- 커널·메일·오류 로그가 비어 있음 (조용한 서버에서 흔함)
- 순환된 이름(.1, .2.gz, -20261103)이 지워진 채 열려 있음 — 순환 뒤 다시 열지 않는 서비스 설정 문제

시각은 판정에 쓰지 않고, 로그 내용의 시각도 해석하지 않는다 (18.04·24.04 형식 차이와 무관).
"""
import fnmatch
import posixpath
import re
import stat

from .. import timefmt
from ..collectors.processes import DELETED, describe, processes
from .base import Check, Context, Evidence
from .fs_06 import APACHE_CONF, NGINX_CONF, config_paths

RSYSLOG_CONF = "/etc/rsyslog.conf"
LOG_DIR = "/var/log/"
JOURNAL_DIR = "/var/log/journal/"
APACHE_LOG_DIR = "/var/log/apache2"
NUL_SCAN = 1024 * 1024
MAX_INCLUDES = 64

ROTATED = re.compile(r"^(?P<base>.+?)(?:\.(?P<num>\d+)|-\d{8}(?:\d{2})?)(?:\.(?:gz|xz|bz2|zst|lz4|Z))?$")
LEGACY_INCLUDE = re.compile(r"^\$IncludeConfig\s+(\S+)", re.I)
INCLUDE_FN = re.compile(r"\binclude\s*\(([^)]*)\)", re.I | re.S)
ACTION_FN = re.compile(r"\baction\s*\(([^)]*)\)", re.I | re.S)
IF_THEN = re.compile(r"^if\b.*\bthen\s+-?(/[^\s;]+)", re.I)
PARAM = re.compile(r"\b(\w+)\s*=\s*\"([^\"]*)\"")


def rotated_base(path):
    """순환된 이름이면 원래 이름 (/var/log/auth.log.2.gz → /var/log/auth.log), 아니면 None."""
    m = ROTATED.match(path)
    return m.group("base") if m else None


def selector_kind(selector):
    """rsyslog 선택자로 이 로그가 계속 기록되는 종류인지 본다.

    'auth': 인증 로그 (auth·authpriv 시설), 'all': 전체 로그 (*.*), None: 그 밖 (커널·메일 등)."""
    kind = None
    for part in selector.split(";"):
        if "." not in part:
            continue
        facs, prio = part.rsplit(".", 1)
        if prio.strip().lower() in ("none", "!*"):
            continue
        names = {f.strip().lower() for f in facs.split(",")}
        if names & {"auth", "authpriv"}:
            return "auth"
        if "*" in names:
            kind = "all"
    return kind


def kind_by_name(path):
    name = posixpath.basename(path)
    if name in ("auth.log", "secure"):
        return "auth"
    if name in ("syslog", "messages"):
        return "all"
    return None


class Target:
    def __init__(self, path, kind, source, origin):
        self.path = path
        self.kind = kind        # 'auth' / 'all' / 'web' / None (비어도 정상인 로그)
        self.source = source    # 어디서 대상이 됐는지 (설정 파일 경로와 줄)
        self.origin = origin    # 'rsyslog' / 'web'


def rsyslog_targets(ctx):
    """rsyslog가 기록하는 파일 목록. rsyslog 설정이 없으면 None."""
    if ctx.stat(RSYSLOG_CONF, follow=True) is None:
        return None
    targets, queue, seen = [], [RSYSLOG_CONF], set()
    while queue and len(seen) < MAX_INCLUDES:
        conf = queue.pop(0)
        if conf in seen:
            continue
        seen.add(conf)
        text = "\n".join(ctx.read_lines(conf, missing_ok=True))
        for no, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith(":") else raw.strip()
            if not line:
                continue
            m = LEGACY_INCLUDE.match(line)
            if m:
                queue += expand(ctx, m.group(1))
                continue
            m = IF_THEN.match(line)  # if $programname == 'x' then /var/log/x.log
            if m:
                path = posixpath.normpath(m.group(1))
                targets.append(Target(path, kind_by_name(path), "{} {}행".format(conf, no), "rsyslog"))
                continue
            if line.startswith(("$", "module(", "global(", "template(", "input(", "include(", "action(",
                                "if ", "ruleset(", "set ", "}")):
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            action = tokens[-1].lstrip("-").split(";", 1)[0]
            if not action.startswith("/"):
                continue  # 원격 전송(@host), 사용자 알림(:omusrmsg:), 동적 파일(?Template) 등
            kind = None if line.startswith(":") else selector_kind(tokens[0])
            targets.append(Target(posixpath.normpath(action), kind or kind_by_name(action), "{} {}행".format(conf, no),
                                  "rsyslog"))
        for m in INCLUDE_FN.finditer(text):
            params = {k.lower(): v for k, v in PARAM.findall(m.group(1))}
            if params.get("file"):
                queue += expand(ctx, params["file"])
        for m in ACTION_FN.finditer(text):
            params = {k.lower(): v for k, v in PARAM.findall(m.group(1))}
            if params.get("type", "").lower() == "omfile" and params.get("file", "").startswith("/"):
                path = posixpath.normpath(params["file"])
                targets.append(Target(path, kind_by_name(path), "{} (action omfile)".format(conf), "rsyslog"))
    return targets


def expand(ctx, pattern):
    """Include 대상 (글롭·디렉터리)을 실제 파일 목록으로."""
    if pattern.endswith("/"):
        return [posixpath.join(pattern, n) for n in ctx.list_dir(pattern)]
    d, name = posixpath.split(pattern)
    return [posixpath.join(d, n) for n in ctx.list_dir(d) if fnmatch.fnmatch(n, name)]


def web_targets(ctx):
    targets = []
    for path in config_paths(ctx, NGINX_CONF):
        for no, raw in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
            s = raw.split("#", 1)[0]
            for m in re.finditer(r"(?:^|[{;])\s*(access_log|error_log)\s+([^;\s]+)", s):
                if m.group(2).startswith("/"):
                    kind = "web" if m.group(1) == "access_log" else None
                    targets.append(Target(posixpath.normpath(m.group(2)), kind, "{} {}행".format(path, no), "web"))
    for path in config_paths(ctx, APACHE_CONF):
        for no, raw in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
            s = raw.split("#", 1)[0].strip()
            m = re.match(r"^(CustomLog|ErrorLog|TransferLog)\s+\"?([^\"\s]+)", s, re.I)
            if m and not m.group(2).startswith("|"):
                p = m.group(2).replace("${APACHE_LOG_DIR}", APACHE_LOG_DIR)
                if p.startswith("/"):
                    kind = None if m.group(1).lower() == "errorlog" else "web"
                    targets.append(Target(posixpath.normpath(p), kind, "{} {}행".format(path, no), "web"))
    return targets


def leading_nul(data):
    return len(data) - len(data.lstrip(b"\0"))


class Log01(Check):
    id = "LOG-01"
    title = "로그 파일이 비었거나 잘림"
    severity = "critical"
    attack = "T1070.002"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        rsys = rsyslog_targets(ctx)
        targets = {}
        for t in (rsys or []) + web_targets(ctx):
            old = targets.get(t.path)
            if old is None or (old.kind is None and t.kind is not None):
                targets[t.path] = t

        findings = []
        held, rotated_held = self.held_logs(ctx, table)
        for path in sorted(held):
            findings.append(self.report_deleted(ctx, path, held[path]))
        present = 0
        for path in sorted(targets):
            st = ctx.stat(path, follow=True)
            if st is not None and stat.S_ISREG(st.st_mode):
                present += 1
                f = self.check_content(ctx, targets[path], st)
                if f:
                    findings.append(f)
            f = self.check_chain(ctx, path, st, path in held)
            if f:
                findings.append(f)

        rs = sum(1 for t in targets.values() if t.origin == "rsyslog")
        web = len(targets) - rs
        if rsys is None:
            parts = ["rsyslog 없음 (journald만)"]
        else:
            parts = ["rsyslog 대상 {}개".format(rs)]
        parts.append("웹 로그 {}개".format(web))
        if targets:
            rest = len(targets) - present
            parts.append("그중 있는 파일 {}개{}".format(present, " (나머지 {}개는 아직 만들어지지 않음)".format(rest) if rest else ""))
        writers = {p.pid for p, _, t in table.open_files(ctx) if t.startswith(LOG_DIR)}
        parts.append("로그를 연 프로세스 {}개".format(len(writers)))
        if rotated_held:
            parts.append("순환된 이름으로 지워진 채 열린 파일 {}개 (순환 뒤 다시 열지 않은 서비스)".format(rotated_held))
        if table.fd_denied:
            parts.append("열린 파일을 읽지 못한 프로세스 {}개".format(len(table.fd_denied)))
        self.scope = ", ".join(parts)
        return findings

    # --- 지워진 채 열린 로그 ---

    def held_logs(self, ctx, table):
        held, rotated = {}, 0
        for p, fd, target in table.open_files(ctx):
            if not target.endswith(DELETED):
                continue
            path = target[:-len(DELETED)]
            if not path.startswith(LOG_DIR) or path.startswith(JOURNAL_DIR):
                continue
            if rotated_base(path):
                rotated += 1
                continue
            held.setdefault(path, []).append((p, fd))
        return held, rotated

    def report_deleted(self, ctx, path, holders):
        now_st = ctx.stat(path, follow=True)
        p, fd = holders[0]
        fd_path = "/proc/{}/fd/{}".format(p.pid, fd)
        orig = ctx.stat(fd_path, follow=True)
        if now_st is None:
            state = "지금 경로에 파일이 없다 (지워짐)"
        else:
            state = "지금 경로에는 다른 파일이 있다 (내용을 바꿔 다시 저장한 흔적)"
        evidence = [Evidence("/proc/{}".format(q.pid), "fd {} → {}{} | {}".format(n, path, DELETED, describe(q, ctx.now)))
                    for q, n in holders[:5]]
        if orig is not None:
            evidence.append(Evidence(fd_path, "프로세스가 붙잡은 원래 파일: inode {}, 크기 {:,}바이트".format(orig.st_ino, orig.st_size)))
        if now_st is not None:
            evidence.append(Evidence(path, "지금 파일: inode {}, 크기 {:,}바이트, 내용 변경(mtime) {}".format(
                now_st.st_ino, now_st.st_size, timefmt.describe(now_st.st_mtime, ctx.now)[0])))
        return self.finding(
            reason="{}: 기록 중인 프로세스 {}개가 지워진 원래 파일을 붙잡고 있다 — {}".format(path, len(holders), state),
            next_steps="원래 내용은 아직 '{}'로 읽을 수 있다. 프로세스를 재시작하기 전에 'cp {} <보존 경로>'로 복사해 두고, "
                       "지금 파일과 비교해 지워진 줄(접속 IP, 계정, 시각)을 찾는다.".format(fd_path, fd_path),
            evidence=evidence,
        )

    # --- 내용 ---

    def check_content(self, ctx, target, st):
        path = target.path
        data = ctx.read_head(path, NUL_SCAN)
        nul = leading_nul(data)
        if nul:
            rest = data[nul:].split(b"\n", 1)[0].decode("utf-8", "replace")[:120]
            size = "{:,}바이트{}".format(nul, " 이상" if nul == len(data) == NUL_SCAN else "")
            return self.finding(
                reason="{}: 파일 앞부분 {}가 NUL(0 바이트)로 채워져 있다 — 기록 중인 파일을 비운 흔적".format(path, size),
                next_steps="비운 시점은 NUL 다음 첫 줄의 시각 무렵이다. 그 전 기록은 순환 파일(.1)이나 원격 로그 서버, journal에서 찾는다.",
                evidence=[Evidence(path, "앞부분 NUL {}, 이어지는 첫 줄: {}".format(size, rest or "(없음)")),
                          Evidence(path, "크기 {:,}바이트".format(st.st_size))] + self.times(ctx, path, st),
            )
        if st.st_size != 0 or target.kind is None:
            return None
        label = {"auth": "인증 로그", "all": "전체 로그", "web": "웹 접근 로그"}[target.kind]
        return self.finding(
            reason="{}: 계속 기록되는 {}가 비어 있다 (순환 직후가 아니라면 비운 흔적)".format(path, label),
            next_steps="순환 시각(logrotate 기록, /var/lib/logrotate/status)과 비교하고, 직전 순환 파일(.1)의 마지막 줄 이후 기록이 어디 갔는지 확인한다.",
            evidence=self.size_evidence(ctx, path, st),
            severity="warning",
        )

    def size_evidence(self, ctx, path, st):
        ev = [Evidence(path, "크기 0바이트 (설정: {})".format(path))]
        prev = ctx.stat(path + ".1", follow=True)
        ev.append(Evidence(path + ".1", "직전 순환 파일 크기 {:,}바이트".format(prev.st_size) if prev else "직전 순환 파일 없음"))
        return ev + self.times(ctx, path, st)

    @staticmethod
    def times(ctx, path, st):
        return [Evidence(path, "내용 변경(mtime): {}".format(timefmt.describe(st.st_mtime, ctx.now)[0])),
                Evidence(path, "속성 변경(ctime): {}".format(timefmt.describe(st.st_ctime, ctx.now)[0]))]

    # --- 순환 사슬 ---

    def check_chain(self, ctx, path, st, held):
        d, name = posixpath.split(path)
        numbers = []
        for n in ctx.list_dir(d):
            m = ROTATED.match(n)
            if m and m.group("base") == name and m.group("num"):
                numbers.append(int(m.group("num")))
        if not numbers:
            return None
        numbers = sorted(set(numbers))
        missing = [n for n in range(1, numbers[-1] + 1) if n not in numbers]
        if st is None and not held:
            reason = "{}: 현재 로그 파일은 없는데 순환 파일 {}개가 있다".format(path, len(numbers))
        elif missing:
            reason = "{}: 순환 파일 사이가 비어 있다 — {} 번이 없다".format(path, ", ".join(str(n) for n in missing[:10]))
        else:
            return None
        return self.finding(
            reason=reason,
            next_steps="logrotate 설정(rotate 개수)이 바뀐 것인지 확인하고, 아니면 빠진 기간의 기록을 원격 로그 서버나 백업에서 찾는다.",
            evidence=[Evidence(d, "있는 순환 번호: {}".format(", ".join(str(n) for n in numbers[:20]))),
                      Evidence(path, "현재 파일: {}".format("있음" if st is not None else "없음"))],
            severity="warning",
        )
