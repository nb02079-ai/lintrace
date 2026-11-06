"""PRC-07 LD_PRELOAD 환경변수 프로세스.

환경변수 LD_PRELOAD(또는 LD_AUDIT)로 라이브러리를 끼워 넣으면 그 프로세스의 함수 호출을 가로챌 수 있다
(비밀번호 가로채기, 결과 숨기기). /etc/ld.so.preload(PER-05)와 달리 특정 프로세스에만 걸린다.

판정 (위험): 환경변수에 LD_PRELOAD·LD_AUDIT가 있는 프로세스. 라이브러리가 임시 폴더·숨김 경로이거나
패키지에 속하지 않으면 근거에 표시한다.
"""
from ..collectors.packages import packages
from ..collectors.processes import describe, processes
from .base import Check, Context, Evidence, Unavailable
from .prc_01 import odd_location

VARS = ("LD_PRELOAD", "LD_AUDIT")


def environ(ctx, pid):
    try:
        raw = ctx.read_head("/proc/{}/environ".format(pid), 256 * 1024)
    except Unavailable:
        return None
    out = {}
    for item in raw.split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
    return out


class Prc07(Check):
    id = "PRC-07"
    title = "LD_PRELOAD 환경변수 프로세스"
    severity = "warning"
    attack = "T1574.006"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        db = packages(ctx)
        findings, unread = [], 0
        for p in table.procs:
            env = environ(ctx, p.pid)
            if env is None:
                unread += 1
                continue
            for var in VARS:
                if not env.get(var):
                    continue
                notes = []
                for lib in env[var].replace(":", " ").split():
                    where = odd_location(lib) if lib.startswith("/") else None
                    pkg = db.owner(lib) if lib.startswith("/") else None
                    exists = lib.startswith("/") and ctx.stat(lib, follow=True) is not None
                    notes.append("{}: {}{}{}".format(
                        lib, "있음" if exists else "없음(지워졌거나 상대 경로)",
                        ", " + where if where else "",
                        ", 패키지 " + pkg if pkg else (", 패키지에 속하지 않음" if db.available and exists else "")))
                findings.append(self.finding(
                    reason="PID {} '{}'에 {}={}가 설정돼 있다 — 이 프로세스의 함수 호출을 끼워 넣은 라이브러리가 가로챌 수 있다".format(
                        p.pid, p.name, var, env[var]),
                    next_steps="라이브러리를 보존하고(--out) 누가 이 환경변수로 프로세스를 띄웠는지(부모, systemd 유닛의 "
                               "Environment=, 셸 설정 파일) 확인한다.",
                    evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now))] +
                             [Evidence("/proc/{}/environ".format(p.pid), n) for n in notes],
                ))
        self.scope = table.scope(ctx) + (", 환경변수를 읽지 못한 {}개".format(unread) if unread else "")
        return findings
