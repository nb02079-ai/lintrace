"""CMD-01 history의 다운로드 후 실행.

침입자는 셸을 얻으면 도구를 내려받아 실행한다. 명령 기록(.bash_history 등)에 그 흔적이 남는다.

판정 (심각)
- 한 줄에서 내려받아 바로 실행: 'curl … | sh', 'wget -O- … | bash' 등 (PER-01과 같은 패턴)
- 내려받은 파일을 몇 줄(10개 명령) 안에 실행: 'wget http://x/a' → 'chmod +x a' → './a'
유명 설치 스크립트(get.docker.com 등)도 예외로 두지 않는다 — URL을 근거에 보여 판단은 사람이 한다 (2026-11-06 결정 2).
"""
import posixpath
import re
import shlex

from .. import timefmt
from ..collectors.history import history
from .base import Check, Context, Evidence
from .persist import Item, group
from .scriptscan import DOWNLOAD_EXEC

DOWNLOAD = re.compile(r"(?:^|[;&|(\s])(wget|curl|fetch|aria2c|scp|tftp)\b")
WINDOW = 10
RUNNERS = {"sh", "bash", "dash", "zsh", "python", "python2", "python3", "perl", "php", "ruby", "node", "source", "."}


def tokens(cmd):
    try:
        return shlex.split(cmd, comments=True)
    except ValueError:
        return cmd.split()


def downloaded_name(cmd):
    """내려받은 파일 이름(경로) 목록."""
    toks = tokens(cmd)
    out = []
    for i, t in enumerate(toks):
        if t in ("-O", "-o", "--output", "--output-document") and i + 1 < len(toks) and toks[i + 1] != "-":
            out.append(toks[i + 1])
        elif t.startswith("--output-document=") or t.startswith("--output="):
            out.append(t.split("=", 1)[1])
    if not out and toks and posixpath.basename(toks[0]) == "wget":
        urls = [t for t in toks if re.match(r"^(?:https?|ftp)://", t)]
        if urls:
            name = posixpath.basename(urls[0].split("?")[0].rstrip("/"))
            if name:
                out.append(name)
    if toks and posixpath.basename(toks[0]) == "curl" and ("-O" in toks or "--remote-name" in toks):
        urls = [t for t in toks if re.match(r"^(?:https?|ftp)://", t)]
        out += [posixpath.basename(u.split("?")[0].rstrip("/")) for u in urls]
    return [o for o in out if o and o not in ("-", "/dev/null")]


def runs(cmd, name):
    """명령이 내려받은 파일(name)을 실행하거나 실행 권한을 주는지."""
    base = posixpath.basename(name)
    for seg in re.split(r"[;&|]+", cmd):
        toks = tokens(seg.strip())
        if not toks:
            continue
        first = toks[0]
        if first in (name, "./" + base) or (first.endswith("/" + base) and "/" in first):
            return "실행"
        if posixpath.basename(first) in RUNNERS and len(toks) > 1 and posixpath.basename(toks[1]) == base:
            return "{}로 실행".format(posixpath.basename(first))
        if posixpath.basename(first) == "chmod" and any("x" in t for t in toks[1:-1] if not t.startswith("/")) \
                and any(posixpath.basename(t) == base for t in toks[1:]):
            return "실행 권한 부여"
    return None


def when(e, now):
    return timefmt.describe(e.ts, now)[0] if e.ts else "시각 기록 없음"


class Cmd01(Check):
    id = "CMD-01"
    title = "history의 다운로드 후 실행"
    severity = "critical"
    attack = "T1105"

    def run(self, ctx: Context):
        h = history(ctx)
        items = []
        for user, path, count, _ in h.files:
            entries = h.of(path)
            cond, ev = [], []
            for i, e in enumerate(entries):
                if any(p.search(e.cmd) for p in DOWNLOAD_EXEC):
                    cond.append(("critical", "내려받아 바로 실행했다"))
                    ev.append(Evidence(path, "{}행 ({}): {}".format(e.lineno, when(e, ctx.now), e.cmd[:200])))
                    continue
                if not DOWNLOAD.search(e.cmd):
                    continue
                for name in downloaded_name(e.cmd):
                    chain = []
                    for later in entries[i + 1:i + 1 + WINDOW]:
                        how = runs(later.cmd, name)
                        if how:
                            chain.append((later, how))
                    if any(how != "실행 권한 부여" for _, how in chain):
                        cond.append(("critical", "내려받은 파일 {}를 실행했다".format(name)))
                        ev.append(Evidence(path, "{}행 ({}): {}".format(e.lineno, when(e, ctx.now), e.cmd[:200])))
                        for later, how in chain[:3]:
                            ev.append(Evidence(path, "{}행 ({}, {}): {}".format(later.lineno, how, when(later, ctx.now),
                                                                              later.cmd[:200])))
            if cond:
                uniq = []
                for c in cond:
                    if c not in uniq:
                        uniq.append(c)
                items.append(Item(path, uniq, ev[:15]))
        findings = group(self, items, "내려받은 주소와 파일을 확인하고(파일이 남아 있으면 보존 — FS-01), 같은 시각의 로그인 기록(ACC-09)으로 "
                                      "누가 실행했는지 본다. 관리자가 한 정상 설치면 출처를 기록해 둔다.", "명령 기록")
        self.scope = "명령 기록 파일 {}개, 명령 {:,}개".format(len(h.files), len(h.entries))
        return findings
