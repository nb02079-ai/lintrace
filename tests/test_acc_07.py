import base64
import os
import unittest

from lintrace.checks.acc_07 import Acc07, expand_pattern, fingerprint, parse_keys
from lintrace.checks.base import Context, Unavailable

from helpers import FakeRootTest, files_owned_by_root

NOW = 1793600000.0
DAY = 86400

# 실제 ed25519 공개키 형식의 임의 키 (지문 계산용)
KEY_A = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
KEY_B = "AAAAC3NzaC1lZDI1NTE5AAAAIBkx3fBcp/1gZHZ5ix+kbBeeTEWOz7Ah2Y4ktUnOS3Pr"

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "bob:x:1000:1000::/home/bob:/bin/bash\n"
    "insecurity:<hash>:0:0::/:/bin/sh\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


def key(k, comment=""):
    return "ssh-ed25519 {} {}\n".format(k, comment).replace(" \n", "\n")


class TestHelpers(unittest.TestCase):
    def test_fingerprint_matches_ssh_keygen_format(self):
        expected = "SHA256:" + base64.b64encode(
            __import__("hashlib").sha256(base64.b64decode(KEY_A)).digest()).decode().rstrip("=")
        self.assertEqual(fingerprint(KEY_A), expected)
        self.assertIsNone(fingerprint("not-base64!"))

    def test_parse_keys_with_options(self):
        keys = parse_keys([
            "# 주석",
            "",
            'from="10.0.0.1",command="/usr/bin/backup" ssh-ed25519 {} backup@host'.format(KEY_A),
            "garbage line",
        ])
        self.assertEqual(len(keys), 2)
        no, ktype, fp, comment, options = keys[0]
        self.assertEqual((no, ktype, comment), (3, "ssh-ed25519", "backup@host"))
        self.assertIn('command="/usr/bin/backup"', options)
        self.assertEqual(keys[1][4], "해석할 수 없는 줄")

    def test_expand_pattern(self):
        self.assertEqual(expand_pattern(".ssh/authorized_keys", "bob", 1000, "/home/bob"),
                         "/home/bob/.ssh/authorized_keys")
        self.assertEqual(expand_pattern("/etc/ssh/keys/%u", "bob", 1000, "/home/bob"), "/etc/ssh/keys/bob")
        self.assertEqual(expand_pattern("%h/.k/%U", "bob", 1000, "/home/bob"), "/home/bob/.k/1000")
        self.assertEqual(expand_pattern(".ssh/authorized_keys", "insecurity", 0, "/"), "/.ssh/authorized_keys")
        self.assertIsNone(expand_pattern(".ssh/authorized_keys", "x", 1, ""))


class TestAcc07(FakeRootTest):
    def scan(self, files, mtimes=None, modes=None):
        root = self.make_root(dict({"/etc/passwd": PASSWD}, **files))
        # 파일은 실제 현재 시각에 만들어지므로, 고정된 NOW보다 미래가 되지 않게 기본 시각을 맞춘다
        times = {p: NOW - DAY for p in files}
        times.update(mtimes or {})
        for path, ts in times.items():
            os.utime(os.path.join(root, path.lstrip("/")), (ts, ts))
        for path, mode in (modes or {}).items():
            os.chmod(os.path.join(root, path.lstrip("/")), mode)
        return root, Acc07().run(Context(root, now=NOW))

    def test_no_keys(self):
        _, f = self.scan({})
        self.assertEqual(f, [])

    @files_owned_by_root
    def test_normal_user_key_is_info_with_elapsed_time(self):
        path = "/home/bob/.ssh/authorized_keys"
        _, f = self.scan({path: key(KEY_A, "bob@laptop")}, mtimes={path: NOW - 3 * DAY},
                         modes={"/home/bob/.ssh": 0o700, path: 0o600})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "info")
        self.assertIn("'bob' 계정의 SSH 키 1개가 등록되어 있다.", f[0].reason)
        details = [e.detail for e in f[0].evidence]
        self.assertTrue(details[0].startswith("1행: ssh-ed25519 SHA256:"))
        self.assertIn("(bob@laptop)", details[0])
        self.assertTrue(details[-1].startswith("파일 변경: 3일 전 ("))

    @files_owned_by_root
    def test_root_key_is_info(self):
        _, f = self.scan({"/root/.ssh/authorized_keys": key(KEY_A)},
                         modes={"/root/.ssh": 0o700, "/root/.ssh/authorized_keys": 0o600})
        self.assertEqual(f[0].severity, "info")

    def test_uid0_non_root_is_critical(self):
        # lin.security의 insecurity처럼 홈이 '/'인 UID 0 계정
        _, f = self.scan({"/.ssh/authorized_keys": key(KEY_A)},
                         modes={"/.ssh": 0o700, "/.ssh/authorized_keys": 0o600})
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("root 외 UID 0 계정(insecurity)", f[0].reason)

    def test_system_account_is_critical(self):
        _, f = self.scan({"/var/www/.ssh/authorized_keys": key(KEY_A)},
                         modes={"/var/www/.ssh": 0o700, "/var/www/.ssh/authorized_keys": 0o600})
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("시스템 계정(www-data)", f[0].reason)

    def test_system_account_with_forced_command_is_warning(self):
        line = 'command="/usr/bin/git-shell" ssh-ed25519 {} dev\n'.format(KEY_A)
        _, f = self.scan({"/var/www/.ssh/authorized_keys": line},
                         modes={"/var/www/.ssh": 0o700, "/var/www/.ssh/authorized_keys": 0o600})
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("command=", f[0].reason)

    @files_owned_by_root
    def test_old_mtime_does_not_lower_and_recent_does_not_raise(self):
        path = "/home/bob/.ssh/authorized_keys"
        for ts in (NOW - 60, NOW - 8 * 365 * DAY):
            _, f = self.scan({path: key(KEY_A)}, mtimes={path: ts},
                             modes={"/home/bob/.ssh": 0o700, path: 0o600})
            self.assertEqual(f[0].severity, "info")  # 시간 원칙: 시각은 위험도에 영향 없음

    def test_future_mtime_is_warning(self):
        path = "/home/bob/.ssh/authorized_keys"
        _, f = self.scan({path: key(KEY_A)}, mtimes={path: NOW + 30 * DAY},
                         modes={"/home/bob/.ssh": 0o700, path: 0o600})
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("미래", f[0].reason)

    def test_writable_file_and_dir_are_warning(self):
        path = "/home/bob/.ssh/authorized_keys"
        _, f = self.scan({path: key(KEY_A)}, modes={"/home/bob/.ssh": 0o777, path: 0o666})
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("키 파일을 다른 사용자가 쓸 수 있다 (권한 666)", f[0].reason)
        self.assertIn("/home/bob/.ssh를 다른 사용자가 쓸 수 있다 (권한 777)", f[0].reason)

    def test_writable_empty_file_is_still_reported(self):
        path = "/home/bob/.ssh/authorized_keys"
        _, f = self.scan({path: ""}, modes={"/home/bob/.ssh": 0o700, path: 0o666})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")

    def test_foreign_owner_is_warning(self):
        if os.geteuid() != 0:
            self.skipTest("소유자 변경은 root에서만 가능")
        path = "/home/bob/.ssh/authorized_keys"
        root, _ = self.scan({path: key(KEY_A)}, modes={"/home/bob/.ssh": 0o700, path: 0o600})
        os.chown(os.path.join(root, path.lstrip("/")), 4242, 4242)
        f = Acc07().run(Context(root, now=NOW))
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("UID 4242", f[0].reason)

    def test_duplicate_key_across_accounts(self):
        files = {"/root/.ssh/authorized_keys": key(KEY_A),
                 "/home/bob/.ssh/authorized_keys": key(KEY_A) + key(KEY_B)}
        modes = {"/root/.ssh": 0o700, "/home/bob/.ssh": 0o700,
                 "/root/.ssh/authorized_keys": 0o600, "/home/bob/.ssh/authorized_keys": 0o600}
        _, f = self.scan(files, modes=modes)
        dup = [x for x in f if "같은 키" in x.reason]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0].severity, "info")
        self.assertIn("bob(/home/bob/.ssh/authorized_keys)", dup[0].reason)
        self.assertIn("root(/root/.ssh/authorized_keys)", dup[0].reason)

    def test_nonstandard_authorized_keys_file(self):
        files = {
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"
                                    "#AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n",
            "/etc/ssh/sshd_config.d/50-x.conf": "AuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k/%u\n",
            "/var/tmp/.k/bob": key(KEY_B),
        }
        _, f = self.scan(files, modes={"/var/tmp/.k/bob": 0o600})
        config = [x for x in f if "기본 위치가 아닌" in x.reason]
        self.assertEqual(len(config), 1)
        self.assertEqual(config[0].severity, "warning")
        self.assertEqual(config[0].evidence[0].source, "/etc/ssh/sshd_config.d/50-x.conf")
        keys = [x for x in f if x.evidence and x.evidence[0].source == "/var/tmp/.k/bob"]
        self.assertEqual(len(keys), 1)  # 숨긴 경로의 키도 찾는다

    def test_default_ubuntu_config_is_not_flagged(self):
        files = {"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"
                                         "#AuthorizedKeysFile\t.ssh/authorized_keys .ssh/authorized_keys2\n"
                                         "KbdInteractiveAuthentication no\nUsePAM yes\n"}
        _, f = self.scan(files)
        self.assertEqual(f, [])

    def test_fifo_is_not_read(self):
        root = self.make_root({"/etc/passwd": PASSWD, "/home/bob/.ssh": None})
        os.chmod(os.path.join(root, "home/bob/.ssh"), 0o700)
        fifo = os.path.join(root, "home/bob/.ssh/authorized_keys")
        os.mkfifo(fifo, 0o600)
        os.utime(fifo, (NOW - DAY, NOW - DAY))
        f = Acc07().run(Context(root, now=NOW))  # 여기서 멈추면 실패
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("일반 파일이 아닌", f[0].reason)
        self.assertNotIn("미래", f[0].reason)

    def test_unreadable_home_is_unavailable(self):
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")
        root = self.make_root({"/etc/passwd": PASSWD, "/home/bob/.ssh/authorized_keys": key(KEY_A)})
        os.chmod(os.path.join(root, "home/bob"), 0o000)
        self.addCleanup(os.chmod, os.path.join(root, "home/bob"), 0o755)
        with self.assertRaises(Unavailable):
            Acc07().run(Context(root, now=NOW))


if __name__ == "__main__":
    unittest.main()
