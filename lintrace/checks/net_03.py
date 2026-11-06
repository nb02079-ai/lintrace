"""NET-03 /etc/hosts 변조.

/etc/hosts는 DNS보다 먼저 참조된다. 공격자는 업데이트·보안 서버 주소를 자기 서버나 127.0.0.1로 돌려
악성 업데이트를 받게 하거나 백신·보안 도구의 통신을 막는다.

판정
- 참고: localhost·호스트 이름·IPv6 기본 항목 외의 항목
- 위험: 업데이트·패키지·보안 업체 도메인(*.ubuntu.com, pypi.org, github.com, 백신 업체 등)을 다른 주소로 돌림
  (2026-11-06 결정 3)
"""
import re

from .base import Check, Context, Evidence

HOSTS = "/etc/hosts"
DEFAULT_NAMES = re.compile(r"^(?:localhost(?:\.localdomain)?|localhost6(?:\.localdomain6)?|ip6-[\w-]+)$")
SENSITIVE = ("ubuntu.com", "canonical.com", "debian.org", "launchpad.net", "launchpadcontent.net", "snapcraft.io",
             "pypi.org", "pythonhosted.org", "github.com", "githubusercontent.com", "npmjs.org", "npmjs.com",
             "docker.io", "docker.com", "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
             "clamav.net", "virustotal.com", "kaspersky.com", "symantec.com", "mcafee.com", "eset.com", "sophos.com",
             "trendmicro.com", "crowdstrike.com", "sentinelone.com", "wazuh.com", "elastic.co", "letsencrypt.org",
             "rocky-linux.org", "centos.org", "fedoraproject.org", "redhat.com")


class Net03(Check):
    id = "NET-03"
    title = "/etc/hosts 변조"
    severity = "info"
    attack = "T1565.001"

    def run(self, ctx: Context):
        own = {l.strip() for l in ctx.read_lines("/etc/hostname", missing_ok=True) if l.strip()}
        extra, sensitive, entries = [], [], 0
        for no, raw in enumerate(ctx.read_lines(HOSTS, missing_ok=True), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            entries += 1
            ip, names = parts[0], parts[1:]
            odd = [n for n in names if not DEFAULT_NAMES.match(n) and n not in own
                   and not any(n.startswith(o + ".") for o in own)]
            if not odd:
                continue
            ev = Evidence(HOSTS, "{}행: {}".format(no, raw.strip()))
            bad = [n for n in odd if any(n.lower() == d or n.lower().endswith("." + d) for d in SENSITIVE)]
            (sensitive if bad else extra).append((ev, bad or odd, ip))
        findings = []
        if sensitive:
            findings.append(self.finding(
                reason="/etc/hosts가 업데이트·보안 관련 도메인을 다른 주소로 돌린다: {}".format(
                    ", ".join("{} → {}".format(", ".join(n), ip) for _, n, ip in sensitive[:5])),
                next_steps="항목을 지우고, 그동안 이 도메인에서 받은 업데이트·패키지를 다시 검증한다(FS-04). 누가 언제 넣었는지 "
                           "명령 기록·파일 변경 시각으로 본다.",
                evidence=[e for e, _, _ in sensitive[:10]], severity="warning"))
        if extra:
            findings.append(self.finding(
                reason="/etc/hosts에 기본 외 항목 {}개: {}".format(
                    len(extra), ", ".join("{} → {}".format(", ".join(n), ip) for _, n, ip in extra[:5])),
                next_steps="관리자가 넣은 항목인지 확인한다. 모르는 항목이면 그 도메인이 무엇인지와 넣은 시점을 본다.",
                evidence=[e for e, _, _ in extra[:10]]))
        self.scope = "/etc/hosts 항목 {}개".format(entries)
        return findings
