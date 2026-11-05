"""2-A 계정·인증: ACC-02·03·04·05·08·09·10·11, 인증 로그·패키지 수집기."""
import gzip
import hashlib
import os
import time
import unittest

from lintrace.checks.acc_02 import Acc02
from lintrace.checks.acc_03 import Acc03
from lintrace.checks.acc_04 import Acc04, scheme
from lintrace.checks.acc_05 import Acc05
from lintrace.checks.acc_08 import Acc08
from lintrace.checks.acc_09 import Acc09
from lintrace.checks.acc_10 import Acc10
from lintrace.checks.acc_11 import Acc11
from lintrace.checks.base import Context, Unavailable
from lintrace.collectors.authlog import auth_log, parse_line
from lintrace.collectors.packages import packages

from helpers import FakeRootTest, files_owned_by_root

NOW = 1793600000.0  # 2026-11-03 경

# lin.security에서 확인한 실제 상태를 줄인 것
LINSEC_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
                 "sync:x:4:65534:sync:/bin:/bin/sync\n"
                 "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
                 "bob:x:1000:1004:bob:/home/bob:/bin/bash\n"
                 "peter:x:1001:1005:peter:/home/peter:/bin/bash\n"
                 "insecurity:AzERyTIjNOGSu:0:0::/:/bin/sh\n")
LINSEC_SHADOW = ("root:$6$abcdefgh$" + "a" * 86 + ":17710:0:99999:7:::\n"
                 "sync:*:17647:0:99999:7:::\n"
                 "syslog:*:17710:0:99999:7:::\n"
                 "bob:$6$saltsalt$" + "b" * 86 + ":17710:0:99999:7:::\n"
                 "peter:$6$saltsalt$" + "c" * 86 + ":17710:0:99999:7:::\n")
LINSEC_GROUP = ("root:x:0:\nadm:x:4:syslog\ndisk:x:6:\nsudo:x:27:\nshadow:x:42:\nsyslog:x:106:\n"
                "lxd:x:108:\nbob:x:1004:\npeter:x:1005:\ndocker:x:999:peter\nnogroup:x:65534:\n")
LINSEC_SUDOERS = ("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
                  "Cmnd_Alias STRACE = /usr/bin/strace\npeter ALL=(ALL) NOPASSWD: STRACE\n")

U2404_PASSWD = ("root:x:0:0:root:/root:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\n"
                "syslog:x:102:102::/nonexistent:/usr/sbin/nologin\n"
                "postgres:x:110:115:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
                "test:x:1000:1000:test:/home/test:/bin/bash\n")
U2404_SHADOW = ("root:*:20000:0:99999:7:::\nsync:*:20000:0:99999:7:::\nsyslog:!:20000::::::\n"
                "postgres:!:20000::::::\ntest:$y$j9T$salt$" + "d" * 43 + ":20000:0:99999:7:::\n")
U2404_GROUP = ("root:x:0:\nadm:x:4:syslog,test\ndisk:x:6:\nsudo:x:27:test\nshadow:x:42:\nsyslog:x:102:\n"
               "postgres:x:115:\nlxd:x:101:test\ntest:x:1000:\nnogroup:x:65534:\n")


def accounts_root(t, passwd, shadow, group, extra=None):
    files = {"/etc/passwd": passwd, "/etc/shadow": shadow, "/etc/group": group}
    files.update(extra or {})
    return t.make_root(files)


def run(check_class, root, now=NOW):
    c = check_class()
    return c, c.run(Context(root, now=now))


class TestAccounts(FakeRootTest):
    def test_linsecurity_expected(self):
        root = accounts_root(self, LINSEC_PASSWD, LINSEC_SHADOW, LINSEC_GROUP, {"/etc/sudoers": LINSEC_SUDOERS})
        _, f2 = run(Acc02, root)
        self.assertEqual([x.reason.split(":")[0] for x in f2], ["'insecurity' 계정"])
        self.assertIn("/etc/shadow에 항목이 없다", f2[0].reason)
        self.assertIn("<가림>", f2[0].evidence[0].detail)  # 해시를 가린다
        _, f3 = run(Acc03, root)
        self.assertEqual(f3, [])  # sync는 예외
        _, f4 = run(Acc04, root)
        self.assertEqual(len(f4), 1)
        self.assertIn("/etc/passwd에 비밀번호 해시가 직접 들어 있다", f4[0].reason)
        self.assertIn("해시 방식이 약하다 (DES)", f4[0].reason)
        self.assertNotIn("AzER", str([e.detail for e in f4[0].evidence]))  # 해시 내용을 보이지 않는다
        c5, f5 = run(Acc05, root)
        self.assertEqual(len(f5), 1)  # insecurity는 UID 0이라 root 그룹을 따로 보지 않는다
        self.assertIn("'peter' 계정이 'docker' 그룹 구성원이다", f5[0].reason)
        self.assertIn("ACC-06에서도 탐지", f5[0].evidence[-1].detail)

    def test_ubuntu2404_clean(self):
        root = accounts_root(self, U2404_PASSWD, U2404_SHADOW, U2404_GROUP)
        for cls in (Acc02, Acc03, Acc04):
            _, f = run(cls, root)
            self.assertEqual(f, [], cls.id)  # postgres의 bash는 패키지 기본값
        c5, f5 = run(Acc05, root)
        self.assertEqual(f5, [])  # 이미 sudo인 test의 lxd는 새 권한이 아님
        self.assertIn("lxd(test)", c5.scope)
        self.assertIn("sudo(test)", c5.scope)

    def test_account_file_mismatches(self):
        root = accounts_root(self, "root:x:0:0::/root:/bin/bash\nghost:x:1002:4242::/home/g:/bin/bash\n",
                             "root:*:1:::::::\nold:*:1:::::::\n", "root:x:0:\n",
                             {"/var/log/auth.log": "Nov  1 10:00:00 h useradd[9]: new user: name=ghost, UID=1002\n"})
        _, f = run(Acc02, root)
        r = {x.reason.split(":")[0]: x for x in f}
        self.assertIn("기본 그룹 GID 4242가 /etc/group에 없다", r["'ghost' 계정"].reason)
        self.assertIn("new user: name=ghost", r["'ghost' 계정"].evidence[1].detail)
        self.assertIn("/etc/shadow에만 있고", r["'old' 계정"].reason)

    def test_unreadable_shadow_is_unavailable_for_every_check(self):
        """앞 항목이 shadow를 못 읽었다고 다음 항목이 빈 shadow를 '정상'으로 보면 안 된다."""
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")
        from lintrace.__main__ import run_checks
        root = accounts_root(self, LINSEC_PASSWD, LINSEC_SHADOW, LINSEC_GROUP)
        os.chmod(os.path.join(root, "etc", "shadow"), 0o000)
        self.addCleanup(os.chmod, os.path.join(root, "etc", "shadow"), 0o644)
        _, unavailable, _, _ = run_checks(Context(root, now=NOW), [Acc02, Acc04, Acc05])
        self.assertEqual([u[0] for u in unavailable], ["ACC-02", "ACC-04"])

    def test_missing_shadow_does_not_flag_everyone(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/h:/bin/bash\n"})
        c, f = run(Acc02, root)
        self.assertEqual(f, [])
        self.assertIn("shadow 없음", c.scope)

    def test_system_account_with_shell(self):
        root = accounts_root(self, "www-data:x:33:33::/var/www:/bin/bash\nbackup:x:34:34::/var/backups:\n"
                                   "nobody:x:65534:65534::/:/usr/sbin/nologin\n", "", "www-data:x:33:\nbackup:x:34:\n")
        _, f = run(Acc03, root)
        self.assertEqual(len(f), 2)
        self.assertIn("빈 칸 — /bin/sh로 로그인", f[1].reason)

    def test_password_schemes(self):
        self.assertEqual(scheme("$1$x$y"), ("MD5", True))
        self.assertEqual(scheme("$y$j9T$a$b"), ("yescrypt", False))
        self.assertEqual(scheme(""), ("비어 있음", True))
        root = accounts_root(self, "a:x:1000:1000::/h:/bin/bash\nb::1001:1001::/h:/bin/bash\nc:*:1002:1002::/h:/bin/false\n",
                             "a::1:::::::\nb:!:1:::::::\nc:$1$s$h:1:::::::\n", "a:x:1000:\nb:x:1001:\nc:x:1002:\n")
        _, f = run(Acc04, root)
        r = {x.reason.split(":")[0]: x.reason for x in f}
        self.assertIn("/etc/shadow 비밀번호가 비어 있다", r["'a' 계정"])
        self.assertIn("/etc/passwd 비밀번호 칸이 비어 있다", r["'b' 계정"])
        self.assertIn("MD5", r["'c' 계정"])

    def test_admin_groups(self):
        root = accounts_root(self, "root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n"
                                   "dev:x:1000:1000::/h:/bin/bash\nops:x:1001:42::/h:/bin/bash\n",
                             "", "root:x:0:\nsudo:x:27:daemon\ndisk:x:6:dev\nshadow:x:42:\ndocker:x:999:dev\n")
        _, f = run(Acc05, root)
        reasons = sorted(x.reason for x in f)
        self.assertEqual(len(reasons), 4)
        self.assertTrue(any("'dev' 계정이 'disk'" in r for r in reasons))
        self.assertTrue(any("'dev' 계정이 'docker'" in r for r in reasons))
        self.assertTrue(any("'ops' 계정이 'shadow'" in r for r in reasons))  # 기본 그룹으로 소속
        self.assertTrue(any("시스템 계정 'daemon'(UID 1)이 관리자 그룹 'sudo'" in r for r in reasons))


def ssh(ts, msg, iso=False, host="test"):
    if iso:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00", time.gmtime(ts))
    else:
        stamp = time.strftime("%b %e %H:%M:%S", time.localtime(ts))
    return "{} {} sshd[1300]: {}\n".format(stamp, host, msg)


class TestAuthLog(FakeRootTest):
    def test_parse_both_formats(self):
        e = parse_line("2026-11-04T23:44:15.420134+00:00 test sshd[1300]: Accepted password for test from 192.168.16.18 port 61667 ssh2", NOW)
        self.assertEqual((e.host, e.prog, e.pid), ("test", "sshd", "1300"))
        self.assertEqual(e.ts, 1793835855.0)  # 2026-11-04 23:44:15 UTC
        e = parse_line("Nov  1 03:02:25 linsecurity sshd[812]: Accepted password for bob from 192.168.56.1 port 50000 ssh2", NOW)
        self.assertEqual(time.localtime(e.ts)[:6], (2026, 11, 1, 3, 2, 25))  # 연도는 점검 시각에서
        dec = parse_line("Dec 31 23:00:00 h sshd[1]: x", NOW)  # 12월 기록을 11월에 읽으면 작년
        self.assertEqual(time.localtime(dec.ts).tm_year, 2025)
        self.assertIsNone(parse_line("garbage", NOW))

    def test_rotation_gz_and_nul(self):
        old = gzip.compress(ssh(NOW - 3 * 86400, "Accepted password for a from 1.1.1.1 port 1 ssh2").encode())
        root = self.make_root({
            "/var/log/auth.log.2.gz": old,
            "/var/log/auth.log.1": ssh(NOW - 86400, "Accepted password for b from 2.2.2.2 port 1 ssh2"),
            # 24.04 VM처럼 중간에 NUL 구간 (스냅샷 복원)
            "/var/log/auth.log": "\0" * 50 + ssh(NOW - 60, "Accepted password for c from 3.3.3.3 port 1 ssh2", iso=True),
        })
        log = auth_log(Context(root, now=NOW))
        self.assertEqual([e.msg.split()[3] for e in log.sshd()], ["a", "b", "c"])  # 오래된 순
        self.assertEqual(log.scope(), "인증 로그 파일 3개·3줄")

    def test_no_auth_log_is_unavailable(self):
        root = self.make_root({"/etc/hostname": "x\n"})
        with self.assertRaises(Unavailable):
            Acc08().run(Context(root, now=NOW))


class TestSshLogins(FakeRootTest):
    def log_root(self, lines):
        return self.make_root({"/var/log/auth.log": "".join(lines)})

    def test_brute_force_then_success(self):
        t0 = NOW - 7200
        lines = [ssh(t0 + i * 5, "Failed password for invalid user admin{} from 10.6.6.6 port 4{} ssh2".format(i, i)) for i in range(6)]
        lines.append(ssh(t0 + 40, "Accepted password for bob from 10.6.6.6 port 5000 ssh2"))
        lines.append(ssh(t0 + 50, "Failed password for bob from 10.7.7.7 port 1 ssh2"))
        lines.append(ssh(t0 + 60, "Accepted password for bob from 10.7.7.7 port 2 ssh2"))  # 실패 1회는 정상
        c, f = run(Acc08, self.log_root(lines))
        self.assertEqual(len(f), 1)
        self.assertIn("10.6.6.6에서 SSH 로그인 실패 6회 뒤 'bob' 계정으로 로그인 성공", f[0].reason)
        self.assertIn("시도한 계정 6개", f[0].evidence[3].detail)
        self.assertIn("SSH 실패 7건·성공 2건", c.scope)

    def test_failures_outside_window_do_not_count(self):
        t0 = NOW - 10 * 3600
        lines = [ssh(t0 + i, "Failed password for bob from 10.6.6.6 port 1 ssh2") for i in range(5)]
        lines.append(ssh(t0 + 2 * 3600, "Accepted password for bob from 10.6.6.6 port 2 ssh2"))
        _, f = run(Acc08, self.log_root(lines))
        self.assertEqual(f, [])

    def test_new_source_after_baseline(self):
        t0 = NOW - 86400
        lines = [ssh(t0 + i * 600, "Accepted publickey for bob from 192.168.56.1 port 1 ssh2") for i in range(3)]
        lines.append(ssh(t0 + 3000, "Accepted password for bob from 203.0.113.9 port 1 ssh2"))
        lines.append(ssh(t0 + 3600, "Accepted password for test from 198.51.100.1 port 1 ssh2"))  # 기준 없음
        _, f = run(Acc09, self.log_root(lines))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "info")
        self.assertIn("'bob' 계정이 처음 보는 출처 203.0.113.9", f[0].reason)
        self.assertIn("192.168.56.1(3회)", f[0].reason)


class TestSshdConfig(FakeRootTest):
    def test_linsecurity_permit_root_login(self):
        root = self.make_root({"/etc/ssh/sshd_config": "PermitRootLogin yes\nUsePAM yes\nX11Forwarding yes\n"})
        _, f = run(Acc10, root)
        self.assertEqual([(x.severity, x.reason.split(":")[0]) for x in f], [("info", "PermitRootLogin yes")])

    def test_ubuntu2404_default_clean(self):
        root = self.make_root({"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"
                                                       "KbdInteractiveAuthentication no\nUsePAM yes\n",
                               "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n"})
        c, f = run(Acc10, root)
        self.assertEqual(f, [])
        self.assertEqual(c.scope, "설정 파일 2개, 지시어 4개")

    def test_first_value_wins_and_match_blocks(self):
        root = self.make_root({
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
                                    "AuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k/%u\n"
                                    "Match User backup\n  PermitEmptyPasswords yes\n",
            "/etc/ssh/sshd_config.d/10-hard.conf": "PermitRootLogin no\n",  # 먼저 읽혀 이 값이 쓰인다
        })
        _, f = run(Acc10, root)
        r = {x.reason.split(":")[0]: x for x in f}
        self.assertNotIn("PermitRootLogin yes", r)
        self.assertEqual(r["AuthorizedKeysFile이 홈의 .ssh 밖도 키 파일로 쓴다"].severity, "warning")
        self.assertIn("Match 블록 안", r["PermitEmptyPasswords yes"].reason)


SEC = "/lib/x86_64-linux-gnu/security/"
COMMON_AUTH = ("auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\n"
               "auth required pam_permit.so\n")


def md5(data):
    return hashlib.md5(data).hexdigest()


class TestPam(FakeRootTest):
    def pam_root(self, extra=None, unix=b"good-unix"):
        files = {
            "/etc/pam.d/common-auth": COMMON_AUTH,
            "/etc/pam.d/sshd": "@include common-auth\naccount required pam_nologin.so\n",
            "/etc/pam.d/sudo": "auth sufficient pam_rootok.so\n@include common-auth\n",
            SEC + "pam_unix.so": unix, SEC + "pam_deny.so": b"deny", SEC + "pam_permit.so": b"permit",
            SEC + "pam_nologin.so": b"nologin", SEC + "pam_rootok.so": b"rootok",
            # usrmerge: dpkg는 /usr/lib/...로 적는다 (24.04 정답 수집에서 확인)
            "/var/lib/dpkg/info/libpam-modules:amd64.list": "".join(
                "/usr" + SEC + m + "\n" for m in ("pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_nologin.so", "pam_rootok.so")),
            "/var/lib/dpkg/info/libpam-modules:amd64.md5sums": "{}  usr{}pam_unix.so\n".format(md5(b"good-unix"), SEC),
        }
        files.update(extra or {})
        return self.make_root(files)

    def test_default_ubuntu_clean(self):
        c, f = run(Acc11, self.pam_root())
        self.assertEqual(f, [])
        self.assertEqual(c.scope, "PAM 설정 3개, 모듈 5개")

    def test_replaced_pam_unix(self):
        _, f = run(Acc11, self.pam_root(unix=b"backdoored-unix"))
        self.assertEqual(len(f), 1)
        self.assertIn("pam_unix.so", f[0].reason)
        self.assertIn("설치 당시와 다르다 (패키지 libpam-modules)", f[0].reason)
        self.assertIn("MD5 지금 {} / dpkg 기록 {}".format(md5(b"backdoored-unix"), md5(b"good-unix")),
                      [e.detail for e in f[0].evidence])

    def test_module_outside_packages(self):
        _, f = run(Acc11, self.pam_root({"/etc/pam.d/sshd": "auth optional pam_snoop.so\n@include common-auth\n",
                                         SEC + "pam_snoop.so": b"x"}))
        self.assertEqual(len(f), 1)
        self.assertIn("pam_snoop.so", f[0].reason)
        self.assertIn("어느 패키지에도 속하지 않는다", f[0].reason)

    def test_permit_before_deny_is_backdoor(self):
        _, f = run(Acc11, self.pam_root({"/etc/pam.d/sshd": "auth sufficient pam_permit.so\n@include common-auth\n"}))
        self.assertEqual(len(f), 1)
        self.assertIn("/etc/pam.d/sshd의 인증 순서에서 pam_permit.so가 pam_deny.so보다 앞에 'sufficient'", f[0].reason)

    def test_pam_exec_from_temp(self):
        _, f = run(Acc11, self.pam_root({
            "/etc/pam.d/common-auth": "auth optional pam_exec.so expose_authtok /tmp/.x/log.sh\n" + COMMON_AUTH,
            SEC + "pam_exec.so": b"exec",
            "/var/lib/dpkg/info/libpam-modules-bin.list": "/usr" + SEC + "pam_exec.so\n"}))
        self.assertEqual(len(f), 1)
        self.assertIn("pam_exec.so가 /etc/pam.d/common-auth에서 /tmp/.x/log.sh", f[0].reason)


class TestPackages(FakeRootTest):
    def test_usrmerge_both_ways(self):
        root = self.make_root({"/var/lib/dpkg/info/a.list": "/usr/lib/x/a.so\n/bin/su\n"})
        db = packages(Context(root))
        self.assertEqual(db.owner("/lib/x/a.so"), "a")
        self.assertEqual(db.owner("/usr/bin/su"), "a")
        self.assertIsNone(db.owner("/opt/a.so"))
        self.assertIsNone(packages(Context(self.make_root({}))).owner("/bin/su"))


if __name__ == "__main__":
    unittest.main()
