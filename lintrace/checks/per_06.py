"""PER-06 at 예약 작업.

at은 한 번만 실행되는 예약 작업이다. 대기 중인 작업은 /var/spool/cron/atjobs(Debian·Ubuntu)나
/var/spool/at(RHEL)에 셸 스크립트로 남는다 — 실행할 때의 환경 변수와 'cd' 뒤에 사용자가 넣은 명령이 온다.

판정: 대기 작업이 있으면 참고, 명령이 의심 명령이면 심각 (PER-01 cron과 같은 기준, 2026-11-06 결정 4).
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import Item, group, regular, uid_name
from .scriptscan import scan_command

SPOOLS = ["/var/spool/cron/atjobs", "/var/spool/at"]
ENV_EXPORT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*;\s*export\s+[A-Za-z_][A-Za-z0-9_]*\s*$")
MARKER = re.compile(r"^cd\s+.*\|\|\s*\{\s*$")
DELIM = re.compile(r"^marcinDELIMITER[0-9a-f]*$")


def job_commands(lines):
    """at 작업 파일에서 사용자 명령 부분만 [(줄 번호, 명령)].

    Debian at: 환경 변수 export → 'cd 폴더 || {' … '}' → '${SHELL:-/bin/sh} << 'marcinDELIMITER…'' → 명령 →
    구분자 줄. 옛 형식은 '}' 바로 뒤에 명령이 온다.
    """
    start = 0
    for i, line in enumerate(lines):
        if MARKER.match(line.strip()):
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == "}":
                    start = j + 1
                    break
            break
    out = []
    for no, line in enumerate(lines[start:], start=start + 1):
        s = line.strip()
        if not s or s.startswith("#") or ENV_EXPORT.match(s) or s.startswith("umask ") \
                or s.startswith("${SHELL") or DELIM.match(s):
            continue
        out.append((no, s))
    return out


class Per06(Check):
    id = "PER-06"
    title = "at 예약 작업"
    severity = "info"
    attack = "T1053.002"

    def run(self, ctx: Context):
        items, jobs = [], 0
        for spool in SPOOLS:
            for name in ctx.list_dir(spool):
                path = posixpath.join(spool, name)
                if name.startswith(".") or name == "spool" or not regular(ctx, path):
                    continue
                jobs += 1
                lines = ctx.read_lines(path)
                cmds = job_commands(lines)
                st = ctx.stat(path)
                owner = uid_name(ctx, st.st_uid) if st else "?"
                cond = [("info", "'{}' 계정의 at 작업이 실행을 기다린다".format(owner))]
                for _, c in cmds:
                    cond += scan_command(c)
                ev = [Evidence(path, "{}행: {}".format(no, c[:200])) for no, c in cmds[:8]]
                items.append(Item(path, cond, ev or [Evidence(path, "명령을 찾지 못함")]))
        findings = group(self, items, "작업 내용과 실행 예정 시각('atq', 'at -c 번호')을 확인하고, 필요 없으면 'atrm 번호'로 지우기 "
                                      "전에 파일을 보존한다(--out).", "at 작업")
        self.scope = "대기 중인 at 작업 {}개".format(jobs)
        return findings
