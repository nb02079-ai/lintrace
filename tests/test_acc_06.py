import os
import unittest

from lintrace.checks.acc_06 import Acc06, classify, logical_lines, split_top, strip_comment
from lintrace.checks.base import Context, Unavailable

from helpers import FakeRootTest

# Ubuntu 22.04/24.04 기본 sudoers (주석 일부 생략)
UBUNTU_DEFAULT = """\
Defaults\tenv_reset
Defaults\tmail_badpass
Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults\tuse_pty

# User privilege specification
root\tALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo\tALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
"""
SUDOERS_D_README = "#\n# The default /etc/sudoers file created on installation of the\n# sudo package now includes the directive:\n#\n#\t#includedir /etc/sudoers.d\n#\n"

# lin.security의 sudo -l 결과를 sudoers 규칙으로 옮긴 것 (scp가 두 번 들어 있음)
LINSECURITY_BOB = (
    "bob ALL=(ALL) /bin/ash, /usr/bin/awk, /bin/bash, /bin/sh, /bin/csh, /usr/bin/curl, "
    "/bin/dash, /bin/ed, /usr/bin/env, /usr/bin/expect, /usr/bin/find, /usr/bin/ftp, "
    "/usr/bin/less, /usr/bin/man, /bin/more, /usr/bin/scp, /usr/bin/socat, /usr/bin/ssh, "
    "/usr/bin/vi, /usr/bin/zsh, /usr/bin/pico, /usr/bin/rvim, /usr/bin/perl, /usr/bin/tclsh, "
    "/usr/bin/git, /usr/bin/script, /usr/bin/scp\n"
)


class TestHelpers(unittest.TestCase):
    def test_logical_lines_joins_continuation(self):
        lines = ["bob ALL=(ALL) /bin/ls, \\", "    /bin/bash", "x ALL=ALL"]
        self.assertEqual(list(logical_lines(lines)),
                         [(1, "bob ALL=(ALL) /bin/ls,      /bin/bash"), (3, "x ALL=ALL")])

    def test_strip_comment_keeps_uid(self):
        self.assertEqual(strip_comment("#1000 ALL=(ALL) ALL # 메모"), "#1000 ALL=(ALL) ALL")
        self.assertEqual(strip_comment("# 전체 주석"), "")

    def test_split_top_ignores_commas_in_parens(self):
        self.assertEqual(split_top("(root, bob) /bin/ls, /bin/cat", ","),
                         ["(root, bob) /bin/ls", " /bin/cat"])

    def test_classify(self):
        self.assertEqual(classify("/bin/bash"), ("shell", "bash"))
        self.assertEqual(classify("/usr/bin/vim.basic /etc/hosts"), ("escape", "vim.basic"))
        self.assertEqual(classify("/usr/bin/python3.6"), ("escape", "python3.6"))
        self.assertEqual(classify("/bin/cp"), ("write", "cp"))
        self.assertEqual(classify("/bin/cp /srv/a /srv/b"), (None, None))  # 인자 고정
        self.assertEqual(classify("/bin/cp /srv/* /backup/"), ("write", "cp"))
        self.assertEqual(classify("/usr/bin/*"), ("all", "/usr/bin/*"))
        self.assertEqual(classify("/usr/bin/systemctl"), ("escape", "systemctl"))
        self.assertEqual(classify("/usr/sbin/service nginx restart"), (None, None))
        self.assertEqual(classify("sha256:abcd /bin/bash"), ("shell", "bash"))


class TestAcc06(FakeRootTest):
    def run_with(self, sudoers, extra=None):
        files = {"/etc/sudoers": sudoers}
        files.update(extra or {})
        return Acc06().run(Context(self.make_root(files)))

    def test_ubuntu_default_is_clean(self):
        f = self.run_with(UBUNTU_DEFAULT, {"/etc/sudoers.d/README": SUDOERS_D_README})
        self.assertEqual(f, [])

    def test_linsecurity(self):
        f = self.run_with(UBUNTU_DEFAULT + LINSECURITY_BOB)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("'bob'", f[0].reason)
        self.assertIn("셸 6개(ash, bash, csh, dash, sh, zsh)", f[0].reason)
        self.assertIn("파일 쓰기 1개(curl)", f[0].reason)
        self.assertIn("셸 탈출 19개", f[0].reason)  # scp 중복은 하나로 센다
        self.assertNotIn("NOPASSWD", f[0].reason)   # lin.security는 비밀번호를 묻는다
        self.assertEqual(f[0].evidence[0].source, "/etc/sudoers")

    def test_escape_only_is_warning(self):
        f = self.run_with("alice ALL=(ALL) /usr/bin/less /var/log/syslog\n")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")

    def test_nopasswd_raises_to_critical(self):
        f = self.run_with("alice ALL=(ALL) NOPASSWD: /usr/bin/vi\n")
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("NOPASSWD", f[0].reason)

    def test_nopasswd_only_on_safe_command_does_not_raise(self):
        f = self.run_with("alice ALL=(ALL) NOPASSWD: /usr/sbin/service nginx restart, PASSWD: /usr/bin/less\n")
        self.assertEqual(f[0].severity, "warning")

    def test_all_for_normal_user_is_critical(self):
        f = self.run_with("deploy ALL=(ALL:ALL) ALL\n")
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("명령 전체", f[0].reason)

    def test_non_root_runas_is_ignored(self):
        self.assertEqual(self.run_with("deploy ALL=(www-data) /bin/bash\n"), [])
        self.assertEqual(self.run_with("deploy ALL=(:adm) /bin/bash\n"), [])

    def test_runas_carries_to_following_commands(self):
        f = self.run_with("deploy ALL=(www-data) /usr/bin/vi, (root) /bin/bash\n")
        self.assertIn("셸 1개(bash)", f[0].reason)
        self.assertNotIn("셸 탈출", f[0].reason)

    def test_negated_command_is_not_counted(self):
        self.assertEqual(self.run_with("alice ALL=(ALL) /usr/sbin/service, !/bin/bash\n"), [])

    def test_aliases_and_includedir(self):
        f = self.run_with(UBUNTU_DEFAULT, {
            "/etc/sudoers.d/ops": "User_Alias OPS = carol, dave\n"
                                  "Cmnd_Alias SHELLS = /bin/sh, /bin/bash\n"
                                  "OPS ALL = (ALL) NOPASSWD: SHELLS\n",
            "/etc/sudoers.d/ops.bak": "eve ALL=(ALL) ALL\n",   # '.' 들어간 파일은 sudo가 읽지 않음
            "/etc/sudoers.d/ops~": "mallory ALL=(ALL) ALL\n",  # '~'로 끝나는 파일도 무시
        })
        self.assertEqual(len(f), 1)
        self.assertIn("'carol, dave'", f[0].reason)
        self.assertEqual(f[0].evidence[0].source, "/etc/sudoers.d/ops")
        self.assertEqual(f[0].severity, "critical")

    def test_include_loop_does_not_hang(self):
        f = self.run_with("@include /etc/sudoers\nbob ALL=(ALL) /bin/sh\n")
        self.assertEqual(len(f), 1)

    def test_continuation_reports_first_line(self):
        f = self.run_with("# 메모\nbob ALL=(ALL) /bin/ls, \\\n    /bin/bash\n")
        self.assertTrue(f[0].evidence[0].detail.startswith("2행: "))

    def test_no_sudo_installed(self):
        self.assertEqual(Acc06().run(Context(self.make_root({"/etc": None}))), [])

    def test_unreadable_is_unavailable(self):
        root = self.make_root({"/etc/sudoers": "bob ALL=(ALL) /bin/sh\n"})
        os.chmod(os.path.join(root, "etc", "sudoers"), 0o000)
        self.addCleanup(os.chmod, os.path.join(root, "etc", "sudoers"), 0o600)
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")
        with self.assertRaises(Unavailable):
            Acc06().run(Context(root))

    def test_directory_instead_of_file_is_unavailable(self):
        with self.assertRaises(Unavailable):
            Acc06().run(Context(self.make_root({"/etc/sudoers": None})))


if __name__ == "__main__":
    unittest.main()
