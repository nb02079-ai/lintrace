"""NET-05 iptables/nftables 규칙 변경.

기준선(3단계) 전에는 '바뀌었다'를 알 수 없으므로, 정상 운영에서 드문 규칙 형태를 본다.
- DNAT·REDIRECT: 특정 출발지의 80번 접속을 22번으로 돌리는 식의 숨은 입구
- string·u32·bpf 매치: 특정 내용의 패킷에만 반응하는 뒷문 (포트 노킹 등)
Docker·Kubernetes·libvirt가 만든 체인(DOCKER*, KUBE-*, CNI-*, LIBVIRT_*)과 docker0 대역 MASQUERADE는 정상
(lin.security 정답, 2026-11-06).

읽는 곳: 'iptables-save'·'ip6tables-save'·'nft list ruleset'(읽기만 하는 명령, 실제 시스템에서만 — 없으면 건너뜀),
저장된 규칙 파일 /etc/iptables/rules.v4·v6, /etc/nftables.conf, /etc/ufw/*.rules
판정: 위 형태의 규칙 → 위험
"""
import re
import shutil
import subprocess

from .base import Check, Context, Evidence

RULE_FILES = ["/etc/iptables/rules.v4", "/etc/iptables/rules.v6", "/etc/nftables.conf", "/etc/ufw/before.rules",
              "/etc/ufw/before6.rules", "/etc/ufw/after.rules", "/etc/ufw/after6.rules", "/etc/ufw/user.rules",
              "/etc/ufw/user6.rules", "/etc/sysconfig/iptables"]
SAFE_CHAINS = re.compile(r"^(?:DOCKER|KUBE-|CNI-|LIBVIRT_|cali-|FLANNEL|ufw)", re.I)
IPT_ODD = [(re.compile(r"-j\s+DNAT\b"), "DNAT(목적지 바꾸기)"), (re.compile(r"-j\s+REDIRECT\b"), "REDIRECT(포트 돌리기)"),
           (re.compile(r"-m\s+string\b"), "string 매치(패킷 내용에 반응)"), (re.compile(r"-m\s+u32\b"), "u32 매치(패킷 바이트에 반응)"),
           (re.compile(r"-m\s+bpf\b"), "bpf 매치")]
NFT_ODD = [(re.compile(r"\bdnat\s+(?:ip6?\s+)?to\b"), "DNAT(목적지 바꾸기)"), (re.compile(r"\bredirect\s+to\b"), "REDIRECT(포트 돌리기)"),
           (re.compile(r"@(?:th|ih|nh|ll),\d+,\d+"), "원시 바이트 매치(패킷 내용에 반응)")]


def run_cmd(args):
    exe = shutil.which(args[0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe] + args[1:], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def odd_iptables(lines, source):
    out = []
    for no, line in enumerate(lines, start=1):
        m = re.match(r"^-A\s+(\S+)\s+(.*)$", line.strip())
        if not m or SAFE_CHAINS.match(m.group(1)) or "docker0" in line or re.search(r"-[jg]\s+(?:DOCKER|KUBE-|CNI-)", line):
            continue
        for rx, what in IPT_ODD:
            if rx.search(m.group(2)):
                out.append((what, Evidence(source, "{}행: {}".format(no, line.strip()[:200]))))
    return out


def odd_nft(lines, source):
    out, table, chain = [], "", ""
    for no, line in enumerate(lines, start=1):
        s = line.strip()
        m = re.match(r"^table\s+\S+\s+(\S+)", s)
        if m:
            table = m.group(1)
            continue
        m = re.match(r"^chain\s+(\S+)", s)
        if m:
            chain = m.group(1)
            continue
        if "docker" in table.lower() or SAFE_CHAINS.match(chain) or "docker0" in s:
            continue
        for rx, what in NFT_ODD:
            if rx.search(s):
                out.append((what, Evidence(source, "{}행 (table {}, chain {}): {}".format(no, table, chain, s[:200]))))
    return out


class Net05(Check):
    id = "NET-05"
    title = "iptables/nftables 규칙 변경"
    severity = "warning"
    attack = "T1562.004"

    def live_rules(self, ctx):
        """{출처 이름: 출력 텍스트} — 테스트에서 바꿔 끼운다."""
        if ctx.root != "/":
            return {}
        out = {}
        for args in (["iptables-save"], ["ip6tables-save"], ["nft", "list", "ruleset"]):
            text = run_cmd(args)
            if text is not None:
                out[" ".join(args)] = text
        return out

    def run(self, ctx: Context):
        hits, sources, rules = [], [], 0
        for name, text in self.live_rules(ctx).items():
            lines = text.splitlines()
            sources.append(name)
            rules += sum(1 for l in lines if l.startswith("-A") or l.strip().startswith(("ip ", "tcp ", "udp ", "meta ")))
            hits += odd_nft(lines, name) if name.startswith("nft") else odd_iptables(lines, name)
        for path in RULE_FILES:
            lines = ctx.read_lines(path, missing_ok=True)
            if not lines:
                continue
            sources.append(path)
            hits += odd_nft(lines, path) if path.endswith("nftables.conf") else odd_iptables(lines, path)
        findings = []
        if hits:
            kinds = []
            for what, _ in hits:
                if what not in kinds:
                    kinds.append(what)
            findings.append(self.finding(
                reason="방화벽에 정상 운영에서 드문 규칙 {}개: {}".format(len(hits), ", ".join(kinds)),
                next_steps="규칙의 출발지·포트와 넣은 사람을 확인한다. 모르는 규칙이면 보존한 뒤('iptables-save > 파일') 지우고, "
                           "저장된 규칙 파일에도 있으면 함께 지운다.",
                evidence=[e for _, e in hits[:15]]))
        self.scope = "규칙 출처 {}개 ({}){}".format(len(sources), ", ".join(sources) or "없음",
                                                ", 실행 중 규칙 {}줄".format(rules) if rules else "")
        return findings
