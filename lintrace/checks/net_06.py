"""NET-06 promiscuous 모드 인터페이스.

promiscuous 모드면 자기에게 오지 않은 패킷까지 받는다 (스니퍼). /sys/class/net/<인터페이스>/flags의
IFF_PROMISC(0x100)를 본다.

판정 (위험). 예외: 브리지 포트(/sys/class/net/<이름>/brport가 있음)와 veth — 브리지(도커 등)에 붙은
인터페이스는 원래 promiscuous다. packet 소켓을 연 프로세스를 근거로 함께 보여준다 (PRC-06).
"""
from ..collectors.processes import processes
from ..collectors.sockets import sockets
from .base import Check, Context, Evidence

IFF_PROMISC = 0x100
NET = "/sys/class/net"


class Net06(Check):
    id = "NET-06"
    title = "promiscuous 모드 인터페이스"
    severity = "warning"
    attack = "T1040"

    def run(self, ctx: Context):
        names = ctx.list_dir(NET)
        findings, bridged = [], 0
        for name in names:
            lines = ctx.read_lines("{}/{}/flags".format(NET, name), missing_ok=True)
            try:
                flags = int(lines[0], 16)
            except (IndexError, ValueError):
                continue
            if not flags & IFF_PROMISC:
                continue
            if name.startswith("veth") or ctx.stat("{}/{}/brport".format(NET, name)) is not None:
                bridged += 1
                continue
            ev = [Evidence("{}/{}/flags".format(NET, name), "flags {} (IFF_PROMISC 0x100 켜짐)".format(lines[0]))]
            processes(ctx)  # packet 소켓의 주인을 찾으려면 프로세스 표가 필요하다
            for s in sockets(ctx).of(("packet",)):
                for p, fd in s.owners:
                    ev.append(Evidence("/proc/{}".format(p.pid), "packet 소켓을 연 프로세스: PID {} {} ({})".format(
                        p.pid, p.name, p.cmdline)))
            findings.append(self.finding(
                reason="인터페이스 {}가 promiscuous 모드다 — 다른 호스트로 가는 패킷까지 받는 스니퍼가 돌고 있을 수 있다".format(name),
                next_steps="packet 소켓을 연 프로세스(PRC-06)를 확인하고, 정상 도구(tcpdump 등)가 아니면 실행 파일을 보존한다.",
                evidence=ev[:8],
            ))
        self.scope = "인터페이스 {}개{}".format(len(names), ", 브리지 포트·veth {}개 제외".format(bridged) if bridged else "")
        return findings
