"""NET-04 resolv.conf 변조.

DNS 서버를 바꾸면 모든 도메인 응답을 공격자가 정한다. Ubuntu는 systemd-resolved가 /etc/resolv.conf를
스텁(127.0.0.53) 링크로 관리하고, 실제 DNS 서버는 netplan·DHCP에서 온다.

판정 (위험)
- /etc/resolv.conf가 관리 도구(resolved·NetworkManager·resolvconf)의 링크가 아니고, 적힌 DNS 서버가
  netplan 설정·DHCP 임대 정보·resolved가 받은 서버에 없음
- resolved.conf가 패키지 원본과 다르거나 덮어쓰기 파일(resolved.conf.d)이 DNS=·FallbackDNS=를 정함
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import file_state, regular

RESOLV = "/etc/resolv.conf"
MANAGED = ("/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf",
           "/run/NetworkManager/resolv.conf", "/run/resolvconf/resolv.conf", "/var/run/NetworkManager/resolv.conf")
RESOLVED = "/etc/systemd/resolved.conf"
DROPINS = ["/etc/systemd/resolved.conf.d", "/run/systemd/resolved.conf.d", "/usr/lib/systemd/resolved.conf.d"]
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]*:[0-9a-fA-F:]+\b")


def nameservers(lines):
    return [l.split()[1] for l in lines if l.strip().startswith("nameserver") and len(l.split()) > 1]


def known_servers(ctx):
    known = set(nameservers(ctx.read_lines("/run/systemd/resolve/resolv.conf", missing_ok=True)))
    for d in ["/etc/netplan", "/run/netplan", "/lib/netplan"]:
        for n in ctx.list_dir(d):
            if n.endswith(".yaml"):
                known.update(IP.findall(" ".join(ctx.read_lines(posixpath.join(d, n), missing_ok=True))))
    for n in ctx.list_dir("/run/systemd/netif/leases"):
        for l in ctx.read_lines(posixpath.join("/run/systemd/netif/leases", n), missing_ok=True):
            if l.startswith("DNS="):
                known.update(l[4:].split())
    for d in ["/var/lib/dhcp", "/var/lib/NetworkManager"]:
        for n in ctx.list_dir(d):
            if "lease" in n:
                for l in ctx.read_lines(posixpath.join(d, n), missing_ok=True):
                    if "domain-name-servers" in l:
                        known.update(IP.findall(l))
    return known


class Net04(Check):
    id = "NET-04"
    title = "resolv.conf 변조"
    severity = "warning"
    attack = "T1565.001"

    def run(self, ctx: Context):
        findings = []
        real = ctx.realpath(RESOLV)
        managed = real in MANAGED
        servers = nameservers(ctx.read_lines(RESOLV, missing_ok=True))
        if not managed and regular(ctx, RESOLV):
            known = known_servers(ctx)
            odd = [s for s in servers if s not in known and not s.startswith("127.") and s != "::1"]
            if odd:
                findings.append(self.finding(
                    reason="/etc/resolv.conf가 관리 도구의 링크가 아니고, 설정·DHCP에 없는 DNS 서버를 쓴다: {}".format(
                        ", ".join(odd)),
                    next_steps="이 DNS 서버가 무엇인지 확인하고, 원래대로 'ln -sf ../run/systemd/resolve/stub-resolv.conf "
                               "/etc/resolv.conf'. 파일이 immutable(FS-09)이면 먼저 'chattr -i'.",
                    evidence=[Evidence(RESOLV, "링크 아님 (일반 파일), nameserver {}".format(", ".join(servers))),
                              Evidence("/run/systemd/resolve/resolv.conf", "알려진 DNS 서버: {}".format(
                                  ", ".join(sorted(known)) or "없음"))]))
        conf_hits = []
        state, pkg = file_state(ctx, RESOLVED) if regular(ctx, RESOLVED) else ("same", None)
        paths = ([RESOLVED] if state == "modified" else []) + [
            posixpath.join(d, n) for d in DROPINS for n in ctx.list_dir(d) if n.endswith(".conf")]
        for path in paths:
            for no, l in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
                s = l.strip()
                if re.match(r"^(?:DNS|FallbackDNS)\s*=\s*\S", s):
                    conf_hits.append(Evidence(path, "{}행: {}".format(no, s)))
        if conf_hits:
            findings.append(self.finding(
                reason="systemd-resolved가 쓸 DNS 서버를 설정 파일에서 직접 정했다 ({}개 줄)".format(len(conf_hits)),
                next_steps="관리자가 정한 DNS인지 확인한다. 모르는 서버면 지우고 'systemctl restart systemd-resolved'.",
                evidence=conf_hits[:10]))
        self.scope = "resolv.conf {} (nameserver {}){}".format(
            "→ " + real if managed else "일반 파일" if regular(ctx, RESOLV) else "없음",
            ", ".join(servers) or "없음", ", resolved.conf {}".format("원본과 다름" if state == "modified" else "기본"))
        return findings
