"""FS-04 패키지 무결성 위반.

패키지가 설치한 파일을 설치 당시 해시(dpkg md5sums)와 비교한다. 루트킷·뒷문은 ls·ps·sshd 같은 실행 파일이나
PAM 모듈, libkeyutils(Ebury) 같은 공유 라이브러리를 바꿔 친다.

범위 (2026-11-06 결정 1)
- 기본: 핵심 경로 — /bin·/sbin·/usr/bin·/usr/sbin의 실행 파일, PAM 모듈, 동적 로더(ld.so), sshd·sudo·login이
  불러오는 라이브러리(libc·libpam·libkeyutils·libcrypt·libaudit·libselinux·libnss·libcrypto·libssl·libz 등)
- --full: 모든 패키지 파일 (수 GB를 읽으므로 느림)
dpkg diversion에 걸린 파일은 원래 파일과 옮긴 파일이 섞여 비교하지 않는다 (범위에 개수).

판정
- 심각: 핵심 경로 파일이 원본과 다름
- 위험: 일반 파일이어야 할 것이 링크로 바뀜
- 참고: 보안 관련 설정 파일(sudoers·crontab·hosts.equiv·pam.d·ssh·sysctl·security·ld.so.conf 등)이 원본과 다름
  — 관리자가 고치는 일이 많아 위험으로 올리지 않는다 (2026-11-06 결정 6). 그 밖 설정 파일 변경·삭제는 범위에 개수
"""
import posixpath
import re
import stat

from ..collectors.packages import packages, path_aliases
from .base import Check, Context, Evidence, Unavailable
from .persist import Item, file_evidence, group, md5_file

CORE_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/security/", "/usr/lib/security/",
             "/lib/x86_64-linux-gnu/security/", "/usr/lib/x86_64-linux-gnu/security/",
             "/lib/aarch64-linux-gnu/security/", "/usr/lib/aarch64-linux-gnu/security/")
CORE_LIBS = re.compile(
    r"^(?:/usr)?/lib(?:64|32)?(?:/[a-z0-9_]+-linux-gnu)?/"
    r"(?:ld-linux[^/]*|ld-[^/]*\.so[^/]*|"
    r"lib(?:c|pam|pam_misc|keyutils|crypt|audit|selinux|nss_files|nss_compat|nss_systemd|wrap|util|systemd|"
    r"crypto|ssl|z|gssapi_krb5|krb5|krb5support|k5crypto|com_err|resolv|dl|pthread|cap|acl|attr)[.-][^/]*)$")
SECURITY_CONF = ("/etc/sudoers", "/etc/crontab", "/etc/cron.", "/etc/hosts.equiv", "/etc/hosts.allow",
                 "/etc/hosts.deny", "/etc/pam.d/", "/etc/pam.conf", "/etc/ssh/", "/etc/sysctl.conf", "/etc/sysctl.d/",
                 "/etc/security/", "/etc/ld.so.conf", "/etc/login.defs", "/etc/profile", "/etc/bash.bashrc",
                 "/etc/environment", "/etc/shells", "/etc/securetty", "/etc/nsswitch.conf")


def core(path):
    if path.startswith(CORE_DIRS) and posixpath.dirname(path) + "/" in CORE_DIRS:
        return True
    return bool(CORE_LIBS.match(path))


class Fs04(Check):
    id = "FS-04"
    title = "패키지 무결성 위반"
    severity = "critical"
    attack = "T1554"

    def run(self, ctx: Context):
        db = packages(ctx)
        if not db.available:
            raise Unavailable("dpkg 정보(/var/lib/dpkg/info)가 없음 — Debian·Ubuntu 계열만 지원")
        full = bool(getattr(ctx, "full", False))
        diverted = db.diverted_paths()
        items, checked, missing, skipped = [], 0, 0, 0
        seen = set()
        for path, (want, pkg) in sorted(db.md5_entries().items()):
            if not full and not core(path):
                continue
            if path_aliases(path) & diverted:
                skipped += 1
                continue
            real = ctx.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            try:
                st = ctx.stat(path)
            except Unavailable:
                continue
            if st is None:
                missing += 1
                continue
            checked += 1
            if stat.S_ISLNK(st.st_mode):  # md5sums에는 일반 파일만 있다
                items.append(Item(path, [("warning", "패키지({})의 일반 파일이 링크로 바뀌었다 → {}".format(pkg, real))],
                                  [Evidence(path, "링크 대상: {}".format(ctx.readlink(path)))]))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            got = md5_file(ctx, path)
            if got is None or got == want:
                continue
            ev = file_evidence(ctx, path, "modified", pkg)
            ev.append(Evidence(path, "MD5 설치 당시 {} → 지금 {}".format(want, got)))
            ev.append(Evidence(path, "SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                ev.append(Evidence(path, "SUID·SGID 파일 (FS-02에서도 확인)"))
            items.append(Item(path, [("critical", "패키지({}) 원본과 내용이 다르다".format(pkg))], ev))

        findings = group(self, items, "같은 버전 패키지의 파일과 비교하고('dpkg --verify 패키지', 'apt download' 후 비교), 바뀐 파일을 "
                                      "보존한다(--out). 실행 파일·라이브러리가 바뀌었다면 이 시스템의 다른 도구 결과도 믿기 어렵다 — "
                                      "외부 매체로 부팅해 다시 본다.", "패키지 파일")

        conf_changed, conf_deleted, security = 0, 0, []
        for path, (want, pkg) in sorted(db.conffiles().items()):
            if path_aliases(path) & diverted:
                continue
            try:
                st = ctx.stat(path, follow=True)
            except Unavailable:
                continue
            if st is None:
                conf_deleted += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            got = md5_file(ctx, path)
            if got is None or got == want:
                continue
            conf_changed += 1
            if path.startswith(SECURITY_CONF):
                security.append((path, pkg))
        if security:
            ev = []
            for path, pkg in security[:15]:
                ev += file_evidence(ctx, path, "modified", pkg)[:2]
            findings.append(self.finding(
                reason="보안 관련 설정 파일 {}개가 패키지 원본과 다르다: {}".format(
                    len(security), ", ".join(p for p, _ in security[:10])),
                next_steps="바뀐 내용이 관리자가 의도한 것인지 확인한다. 권한·인증에 관한 설정(sudoers, pam.d, ssh)은 "
                           "ACC 항목 결과와 함께 본다.",
                evidence=ev[:20], severity="info"))

        self.scope = "{} 패키지 파일 {:,}개 검사 (없음 {:,}개, diversion 제외 {}개), 설정 파일 {:,}개 중 원본과 다름 {}개·삭제 {}개".format(
            "모든(--full)" if full else "핵심 경로", checked, missing, skipped, len(db.conffiles()), conf_changed,
            conf_deleted)
        return findings
