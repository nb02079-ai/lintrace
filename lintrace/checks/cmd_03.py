"""CMD-03 웹 서버 로그의 공격 패턴.

nginx·Apache 접근 로그(combined 형식)에서 요청 경로를 URL 디코딩(두 번)해 공격 유형별로 센다.

판정
- 위험: SQL 인젝션, 경로 조작, 명령 주입, 파일 포함(php://·data:// 등), Log4Shell(${jndi:), 스캐너 User-Agent
  — 유형별 한 건 (출발 IP 상위 5, 처음·마지막 시각, 예시 5줄)
- 심각: FS-06이 웹쉘로 판단한 파일에 대한 요청이 성공(2xx)함 — 실제로 쓰인 흔적
로그 안의 시각은 순서를 보는 데 쓴다. 읽는 양: 로그마다 현재 + 순환 7개, 합계 500MB (2026-11-06 결정 5).
SQL 패턴은 문맥을 본다 — 'imgareaselect.css'의 'select' 같은 단어 일부는 잡지 않는다 (24.04 정답).
"""
import gzip
import os
import posixpath
import re
from urllib.parse import unquote_plus

from .base import Check, Context, Evidence, Unavailable
from .fs_06 import Fs06, config_paths

DEFAULT_LOGS = ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log",
                "/var/log/httpd/access_log"]
ROTATE = 7
TOTAL_LIMIT = 500 * 1024 * 1024
LINE = re.compile(r'^(?:\S+:\d+ )?(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^" ]*)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
PATTERNS = [
    ("SQL 인젝션", re.compile(
        r"\bunion\b(?:\s|/\*.*?\*/|\+)+(?:all\s+)?select\b|\bselect\b.{1,100}\bfrom\b|"
        r"'\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|"
        r"\binformation_schema\b|\b(?:extractvalue|updatexml|load_file)\s*\(|\binto\s+(?:out|dump)file\b|waitfor\s+delay",
        re.I)),
    ("경로 조작", re.compile(r"(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow)\b|/proc/self/(?:environ|cmdline)|win\.ini", re.I)),
    ("명령 주입", re.compile(r"(?:[;|`]|\$\(|%0a)\s*(?:id|whoami|uname|cat\s+/etc|wget|curl|nc|ncat|bash|sh|python\d?|perl)\b",
                         re.I)),
    ("파일 포함(LFI·RFI)", re.compile(r"\b(?:php://(?:filter|input)|data://|expect://|zip://|phar://|file:///)", re.I)),
    ("Log4Shell", re.compile(r"\$\{(?:jndi|\$\{lower|::-j)", re.I)),
]
SCANNERS = re.compile(r"sqlmap|nikto|wpscan|gobuster|dirbuster|dirb\b|nmap|masscan|nuclei|feroxbuster|ffuf|acunetix|"
                      r"nessus|openvas|zgrab|wfuzz|whatweb|hydra", re.I)


def log_paths(ctx):
    found = list(DEFAULT_LOGS)
    for path in config_paths(ctx, ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"]):
        for line in ctx.read_lines(path, missing_ok=True):
            m = re.match(r"^\s*access_log\s+([^\s;]+)", line)
            if m and m.group(1).startswith("/"):
                found.append(m.group(1))
    out = []
    for base in dict.fromkeys(found):
        for name in [base] + ["{}.{}".format(base, i) for i in range(1, ROTATE + 1)] + \
                ["{}.{}.gz".format(base, i) for i in range(1, ROTATE + 1)]:
            if ctx.stat(name, follow=True) is not None:
                out.append(name)
    return out


def read_text(ctx, path, limit):
    full = ctx.path(path)
    try:
        if path.endswith(".gz"):
            with gzip.open(full, "rb") as f:
                data = f.read(limit)
        else:
            with open(full, "rb") as f:
                data = f.read(limit)
    except PermissionError:
        raise Unavailable("{} 읽기 권한 없음 (root로 실행 필요)".format(path))
    except (OSError, EOFError):
        return ""
    return data.decode("utf-8", "replace")


def decode(url):
    once = unquote_plus(url)
    return unquote_plus(once) if "%" in once else once


class Cmd03(Check):
    id = "CMD-03"
    title = "웹 서버 로그의 공격 패턴"
    severity = "warning"
    attack = "T1190"

    def webshells(self, ctx):
        """FS-06이 웹쉘로 판단한 파일 경로 (심각 판정용)."""
        cached = getattr(ctx, "_fs06_paths", None)
        if cached is None:
            cached = set()
            try:
                for f in Fs06().run(ctx):
                    cached.update(e.source for e in f.evidence)
            except Unavailable:
                pass  # 웹 루트를 읽지 못하면 공격 패턴만 본다
            ctx._fs06_paths = cached
        return cached

    def run(self, ctx: Context):
        paths = log_paths(ctx)
        budget, total_lines, parsed = TOTAL_LIMIT, 0, 0
        hits = {}   # 유형 → [(ip, 시각, 줄, 출처)]
        requests = []  # (경로, 상태, ip, 시각, 줄, 출처) — 웹쉘 요청 확인용
        cut = False
        for path in paths:
            if budget <= 0:
                cut = True
                break
            text = read_text(ctx, path, budget)
            budget -= len(text.encode("utf-8", "replace"))
            for no, line in enumerate(text.splitlines(), start=1):
                total_lines += 1
                m = LINE.match(line)
                if not m:
                    continue
                parsed += 1
                ip, ts, method, url, status, ua = m.groups()
                dec = decode(url)
                where = "{} {}행".format(path, no)
                for name, rx in PATTERNS:
                    if rx.search(dec) or (name == "Log4Shell" and ua and rx.search(ua)):
                        hits.setdefault(name, []).append((ip, ts, line, where))
                if ua and SCANNERS.search(ua):
                    hits.setdefault("스캐너 도구", []).append((ip, ts, line, where))
                if status.startswith("2") and ".php" in url.lower():
                    requests.append((url.split("?")[0], status, ip, ts, line, where))

        findings = []
        for name in [p[0] for p in PATTERNS] + ["스캐너 도구"]:
            rows = hits.get(name)
            if not rows:
                continue
            ips = {}
            for ip, *_ in rows:
                ips[ip] = ips.get(ip, 0) + 1
            top = sorted(ips.items(), key=lambda x: -x[1])[:5]
            findings.append(self.finding(
                reason="웹 접근 로그에 {} 시도 {:,}건 — 출발 IP {}개 ({}), 처음 {} · 마지막 {}".format(
                    name, len(rows), len(ips), ", ".join("{} {}건".format(i, n) for i, n in top), rows[0][1], rows[-1][1]),
                next_steps="응답 코드·크기로 성공했는지 보고, 같은 IP의 다른 요청과 그 시각 이후 웹 루트에 생긴 파일(FS-06·07)을 확인한다. "
                           "필요하면 IP를 막는다.",
                evidence=[Evidence(r[3].rsplit(" ", 1)[0], "{}: {}".format(r[3].rsplit(" ", 1)[1], r[2][:240]))
                          for r in rows[:5]]))

        if requests:
            shells = self.webshells(ctx)
            used = {}
            for url, status, ip, ts, line, where in requests:
                for s in shells:
                    if len(url) > 1 and s.endswith(url):
                        used.setdefault(s, []).append((ip, ts, line, where))
            for shell, rows in sorted(used.items()):
                findings.append(self.finding(
                    reason="FS-06이 웹쉘로 판단한 {}에 대한 요청이 {}건 성공했다 — 출발 IP {}, 처음 {} · 마지막 {}".format(
                        shell, len(rows), ", ".join(sorted({r[0] for r in rows})[:5]), rows[0][1], rows[-1][1]),
                    next_steps="웹쉘을 보존하고(--out) 이 IP의 모든 요청과 그 시각의 프로세스·명령 기록(CMD-01·02)을 확인한다.",
                    evidence=[Evidence(r[3].rsplit(" ", 1)[0], "{}: {}".format(r[3].rsplit(" ", 1)[1], r[2][:240]))
                              for r in rows[:5]],
                    severity="critical"))

        self.scope = "웹 로그 {}개, {:,}줄 (형식 해석 {:,}줄){}".format(
            len(paths), total_lines, parsed, " — 500MB에서 멈춤, 일부만 읽음" if cut else "")
        return findings
