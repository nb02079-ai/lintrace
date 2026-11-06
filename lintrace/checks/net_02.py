"""NET-02 외부로 나가는 의심 연결.

IP 대역으로는 판정하지 않는다 (실습망·사내망은 사설 IP라 공격자도 사설 IP다). NET-01과 같이 연결을 잡은
프로세스로 본다 (2026-11-06 결정, 3단계 기준선 전까지).

판정 (위험): 루프백이 아닌 상대와 맺은 TCP 연결을 셸·인터프리터·nc·socat이나 실행 파일이 지워짐·memfd·
임시 폴더·숨김 경로·패키지 밖인 프로세스가 잡고 있음. 리버스 셸이면 PRC-08에서도 심각으로 나온다.
"""
from ..collectors.processes import describe, processes
from ..collectors.sockets import is_loopback, sockets
from .base import Check, Context, Evidence
from .procnet import suspicious


class Net02(Check):
    id = "NET-02"
    title = "외부로 나가는 의심 연결"
    severity = "warning"
    attack = "T1071"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        conns = [s for s in sockets(ctx).socks if s.established and s.remote and not is_loopback(s.remote[0])]
        by_proc = {}
        for s in conns:
            for p, fd in s.owners:
                by_proc.setdefault(p.pid, (p, []))[1].append((s, fd))
        findings = []
        for pid in sorted(by_proc, key=int):
            p, items = by_proc[pid]
            why = suspicious(ctx, p)
            if not why:
                continue
            peers = sorted({"{}:{}".format(*s.remote) for s, _ in items})
            findings.append(self.finding(
                reason="PID {} '{}'가 {}와 연결돼 있다 ({})".format(p.pid, p.name, ", ".join(peers[:5]), ", ".join(why)),
                next_steps="상대 주소의 정체를 확인하고, 연결을 끊기 전에 프로세스와 실행 파일을 보존한다(--out). "
                           "셸이면 PRC-08(리버스 셸)과 함께 본다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now))] +
                         [Evidence("/proc/{}/fd/{}".format(p.pid, fd), s.describe()) for s, fd in items[:5]],
            ))
        self.scope = "루프백 밖 TCP 연결 {}개, 프로세스 {}개".format(len(conns), len(by_proc))
        return findings
