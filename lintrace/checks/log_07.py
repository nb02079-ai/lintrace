"""LOG-07 네트워크 스택의 커널 oops·KASAN 기록.

원격 공격이 커널 네트워크 코드의 버그를 건드리면 커널 로그에 oops·BUG·KASAN·general protection 기록과
함께 호출 스택(Call Trace)이 남는다. 네트워크 함수가 스택에 있으면 원격에서 커널을 공격한 흔적일 수 있다.

판정
- 위험: 커널 crash 기록(oops·BUG:·KASAN·general protection·panic·Call Trace)에 네트워크 스택 함수가 있음
- 참고: 그 밖의 커널 crash 기록
일반 경고·오류(vmwgfx 그래픽 오류, RETBleed 완화 경고 등)는 crash가 아니므로 대상이 아니다.
"""
import re

from ..collectors.journal import journal
from ..timefmt import absolute
from .base import Check, Context, Evidence

# crash의 '시작'을 알리는 표지 (Call Trace:는 스택이라 시작 표지에서 뺀다 — 뒤 기록으로 딸려 들어온다)
START = re.compile(r"\b(?:Oops|BUG:|KASAN|KFENCE|general protection fault|stack segment|kernel panic|"
                   r"unable to handle (?:kernel|page)|bad RIP value|soft lockup|hard LOCKUP|"
                   r"detected stall|watchdog: BUG)\b", re.I)
TRACE_SECS = 5      # crash 시작 뒤 이 시간 안의 커널 기록을 같은 사건의 스택으로 본다
TRACE_MAX = 60
NET_SYM = re.compile(r"\b(?:tcp_|udp_|udpv6_|tcpv6_|ip_|ipv6_|ip6_|inet_|inet6_|__inet|nf_|nft_|ipt_|xt_|"
                     r"skb_|__skb|sk_|__sk|packet_|netif_|netlink_|dev_hard_start|dev_queue|napi_|"
                     r"netdev_|sock_|__sock|af_packet|rtnetlink|neigh_|__netif)", re.I)


class Log07(Check):
    id = "LOG-07"
    title = "네트워크 스택의 커널 oops·KASAN 기록"
    severity = "warning"
    attack = "T1068"

    def run(self, ctx: Context):
        j = journal(ctx)
        if not j.available:
            self.scope = "journal 읽기 불가 ({})".format(j.note)
            return []
        kernel = [r for r in j.records if r.prog == "kernel"]
        kernel.sort(key=lambda r: r.realtime)
        net, other = [], []
        i = 0
        while i < len(kernel):
            r = kernel[i]
            if not START.search(r.msg):
                i += 1
                continue
            # 이 crash의 시작 줄 + 뒤따르는 스택 줄을 한 사건으로 모은다
            trace = [r]
            j2 = i + 1
            while j2 < len(kernel) and j2 - i <= TRACE_MAX and kernel[j2].realtime <= r.realtime + TRACE_SECS \
                    and not START.search(kernel[j2].msg):
                trace.append(kernel[j2])
                j2 += 1
            blob = " ".join(t.msg for t in trace)
            (net if NET_SYM.search(blob) else other).append((r, trace))
            i = j2
        crashes = net + other
        findings = []
        if net:
            findings.append(self.finding(
                reason="커널 네트워크 코드에서 crash 기록 {}건 (oops·BUG·KASAN 등에 네트워크 함수가 있음) — 원격 커널 공격 흔적일 수 있다".format(len(net)),
                next_steps="기록 전후의 전체 호출 스택을 보존하고(journalctl, dmesg), 그 시각의 원격 연결(NET-02)과 그 뒤 새로 "
                           "생긴 root 권한 프로세스(PRC)를 확인한다. 커널을 최신으로 올린다.",
                evidence=[Evidence("journal", "{}: {}".format(absolute(r.realtime), (r.msg + " … " + "; ".join(
                    t.msg for t in tr[1:4])).strip()[:240])) for r, tr in net[:6]]))
        if other:
            findings.append(self.finding(
                reason="커널 crash 기록 {}건 (네트워크 외) — 하드웨어·드라이버 문제일 수 있으나 흔적으로 남긴다".format(len(other)),
                next_steps="기록 내용으로 어느 모듈인지 확인한다. 반복되면 그 드라이버·하드웨어를 점검한다.",
                evidence=[Evidence("journal", "{}: {}".format(absolute(r.realtime), r.msg[:200])) for r, _ in other[:5]],
                severity="info"))
        self.scope = "커널 기록 {:,}건 중 crash 사건 {}건 (네트워크 {}건)".format(len(kernel), len(crashes), len(net))
        return findings
