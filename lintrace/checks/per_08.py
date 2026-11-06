"""PER-08 udev 규칙의 명령 실행.

udev 규칙의 RUN·PROGRAM·IMPORT{program}은 장치가 붙거나 바뀔 때(부팅 포함) root로 명령을 실행한다.
공격자는 자주 생기는 장치 이벤트(예: /dev/random, 네트워크)에 명령을 걸어 지속성을 얻는다.

읽는 곳: /etc/udev/rules.d, /run/udev/rules.d, /lib·/usr/lib/udev/rules.d 의 *.rules
판정
- 위험: 패키지에 속하지 않거나 원본과 다른 규칙 파일이 명령을 실행한다 (RUN{builtin}은 제외)
- 심각: 명령이 의심 명령이거나 실행 대상이 임시 폴더·숨김 경로·홈에 있음, 일반 사용자가 소유·쓸 수 있는 규칙·실행 대상
명령이 없는 규칙(netplan의 90-netplan.rules, snapd의 70-snap.*.rules 등)은 범위에 개수만 (2026-11-06 정답).
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import Item, exec_conditions, file_evidence, file_state, group, owner_issue, regular, unique_dirs

DIRS = ["/etc/udev/rules.d", "/run/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"]
KEY = re.compile(r"\b(RUN(?:\{(program|builtin)\})?|PROGRAM|IMPORT\{program\})\s*(\+?=)\s*\"([^\"]*)\"")
UDEV_LIB = ("/usr/lib/udev", "/lib/udev")


def commands(lines):
    """[(줄 번호, 키, 명령)] — RUN{builtin}은 udev 내장 기능이라 뺀다."""
    out = []
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        for m in KEY.finditer(s):
            if m.group(2) == "builtin":
                continue
            out.append((no, m.group(1) + m.group(3), m.group(4)))
    return out


def resolve(ctx, prog):
    """udev는 '/'로 시작하지 않는 프로그램을 /usr/lib/udev에서 찾는다."""
    if prog.startswith("/"):
        return prog
    for d in UDEV_LIB:
        cand = posixpath.join(d, prog)
        if regular(ctx, cand):
            return cand
    return posixpath.join(UDEV_LIB[0], prog)


class Per08(Check):
    id = "PER-08"
    title = "udev 규칙의 명령 실행"
    severity = "warning"
    attack = "T1546.017"

    def run(self, ctx: Context):
        items, files, foreign = [], 0, 0
        for d in unique_dirs(ctx, DIRS):
            for name in ctx.list_dir(d):
                path = posixpath.join(d, name)
                if not name.endswith(".rules") or not regular(ctx, path):
                    continue
                files += 1
                state, pkg = file_state(ctx, path)
                issue = owner_issue(ctx, path)
                if state not in ("unpackaged", "modified") and not issue:
                    continue
                if state in ("unpackaged", "modified"):
                    foreign += 1
                cmds = commands(ctx.read_lines(path))
                if not cmds:
                    continue
                cond = []
                if state in ("unpackaged", "modified"):
                    cond.append(("warning", "{} 규칙 파일이 장치 이벤트 때 root로 명령 {}개를 실행한다".format(
                        "패키지에 속하지 않는" if state == "unpackaged" else "패키지 원본과 다른", len(cmds))))
                if issue:
                    cond.append(("critical", issue))
                for _, _, cmd in cmds:
                    first = cmd.split()[0] if cmd.split() else ""
                    cond += exec_conditions(ctx, cmd, resolve(ctx, first) if first else "")
                uniq = []
                for c in cond:
                    if c not in uniq:
                        uniq.append(c)
                items.append(Item(path, uniq, file_evidence(ctx, path, state, pkg) +
                                  [Evidence(path, "{}행: {}\"{}\"".format(no, k, c[:150])) for no, k, c in cmds[:6]]))
        findings = group(self, items, "규칙이 어떤 장치 이벤트에 무엇을 실행하는지 확인한다. 필요 없으면 규칙 파일을 보존한 뒤(--out) "
                                      "지우고 'udevadm control --reload'.", "udev 규칙")
        self.scope = "규칙 파일 {}개 (패키지 밖·원본과 다름 {}개)".format(files, foreign)
        return findings
