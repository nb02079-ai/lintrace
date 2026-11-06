"""PRC-06 raw·packet 소켓을 연 프로세스.

raw·packet 소켓은 패킷을 직접 읽고 쓴다. 스니퍼(비밀번호 가로채기)나 포트 노킹 뒷문(BPFDoor 등 — 포트를
열지 않고 특정 패킷이 오면 깨어남)이 쓴다.

판정 (위험): raw·packet 소켓을 연 프로세스.
예외: 실행 파일이 패키지에 속한 네트워크 관리 데몬 (systemd-networkd의 LLDP·ipv6-icmp, DHCP 클라이언트 등 —
두 검증 VM 모두 systemd-networkd만 있었음). tcpdump 같은 수집 도구는 패키지라도 위험으로 낸다
(스니퍼가 돌고 있다는 사실 자체가 확인할 거리).
"""
from ..collectors.processes import describe, processes
from ..collectors.sockets import sockets
from .base import Check, Context, Evidence
from .procnet import NET_DAEMONS, net_daemon  # noqa: F401 (NET_DAEMONS는 예전 위치에서도 쓸 수 있게)


class Prc06(Check):
    id = "PRC-06"
    title = "raw·packet 소켓을 연 프로세스"
    severity = "warning"
    attack = "T1205.002"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        socks = sockets(ctx).of(("raw", "packet"))
        by_proc, allowed, orphan = {}, 0, 0
        for s in socks:
            if not s.owners:
                orphan += 1
            for p, fd in s.owners:
                by_proc.setdefault(p.pid, (p, []))[1].append((s, fd))
        findings = []
        for pid in sorted(by_proc, key=int):
            p, items = by_proc[pid]
            if net_daemon(ctx, p):
                allowed += 1
                continue
            findings.append(self.finding(
                reason="PID {} '{}'가 패킷을 직접 다루는 소켓 {}개를 열었다 ({}) — 스니퍼나 포트 노킹 뒷문일 수 있다".format(
                    p.pid, p.name, len(items), ", ".join(sorted({s.proto for s, _ in items}))),
                next_steps="이 프로그램이 무엇이고 누가 띄웠는지 확인한다. 정상 도구(tcpdump 등)가 아니면 실행 파일을 "
                           "보존하고(--out) 붙어 있는 BPF 필터(어떤 패킷을 기다리는지)를 확인한다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now))] +
                         [Evidence("/proc/{}/fd/{}".format(p.pid, fd), s.describe()) for s, fd in items[:5]],
            ))
        notes = ["네트워크 관리 데몬 {}개 제외".format(allowed)] if allowed else []
        if orphan:
            notes.append("소유 프로세스 없음 {}개".format(orphan))
        self.scope = "raw·packet 소켓 {}개{}".format(len(socks), " ({})".format(", ".join(notes)) if notes else "")
        return findings
