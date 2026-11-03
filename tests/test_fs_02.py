import os
import unittest

from lintrace.checks.base import Context, Unavailable
from lintrace.checks.fs_02 import Fs02, norm_name, path_aliases, unescape_mount, who_can_run

from helpers import FakeRootTest, files_owned_by_root

NOW = 1793600000.0
ELF = "\x7fELF fake binary {}\n"


class TestHelpers(unittest.TestCase):
    def test_norm_name(self):
        self.assertEqual(norm_name("/usr/bin/python3.6"), "python")
        self.assertEqual(norm_name("/usr/bin/vim.basic"), "vim")
        self.assertEqual(norm_name("/usr/bin/traceroute6.iputils"), "traceroute")
        self.assertEqual(norm_name("/bin/ntfs-3g"), "ntfs-3g")

    def test_path_aliases(self):
        self.assertEqual(path_aliases("/usr/bin/su"), {"/usr/bin/su", "/bin/su"})
        self.assertEqual(path_aliases("/bin/su"), {"/bin/su", "/usr/bin/su"})
        self.assertEqual(path_aliases("/usr/local/bin/x"), {"/usr/local/bin/x"})

    def test_unescape_mount(self):
        self.assertEqual(unescape_mount("/mnt/my\\040share"), "/mnt/my share")

    def test_who_can_run(self):
        self.assertEqual(who_can_run(0o104755, "root"), "누구나 실행 가능")
        self.assertEqual(who_can_run(0o104750, "itservices"), "그룹 itservices 구성원만 실행 가능")
        self.assertEqual(who_can_run(0o104700, "root"), "소유자만 실행 가능")


class TestFs02(FakeRootTest):
    def scan(self, files, modes, dpkg=None, extra_setup=None):
        base = {"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                "/etc/group": "root:x:0:\nitservices:x:0:\n"}  # gid 0 이름이 먼저 나온 root로 쓰인다
        base.update(files)
        for pkg, paths in (dpkg or {}).items():
            base["/var/lib/dpkg/info/{}.list".format(pkg)] = "".join(p + "\n" for p in paths)
        root = self.make_root(base)
        for path, mode in modes.items():
            os.chmod(os.path.join(root, path.lstrip("/")), mode)
        if extra_setup:
            extra_setup(root)
        check = Fs02()
        return check, check.run(Context(root, now=NOW))

    @files_owned_by_root
    def test_linsecurity(self):
        """lin.security 정답 재현: 패키지 소속 표준 SUID들 + taskset·xxd"""
        def usrmerge(root):
            os.symlink("usr/bin", os.path.join(root, "bin"))  # /bin → /usr/bin (최신 Ubuntu 형태)
        files = {"/usr/bin/taskset": ELF.format(1), "/usr/bin/xxd": ELF.format(2),
                 "/usr/bin/passwd": ELF.format(3), "/usr/bin/su": ELF.format(4),
                 "/usr/bin/crontab": ELF.format(5), "/usr/bin/ls": ELF.format(6)}
        modes = {"/usr/bin/taskset": 0o6755, "/usr/bin/xxd": 0o4750, "/usr/bin/passwd": 0o4755,
                 "/usr/bin/su": 0o4755, "/usr/bin/crontab": 0o2755, "/usr/bin/ls": 0o755}
        dpkg = {"util-linux": ["/usr/bin/taskset"], "xxd": ["/usr/bin/xxd"], "passwd": ["/usr/bin/passwd"],
                "login": ["/bin/su"],  # dpkg는 옛 경로로 기록 — usrmerge 별칭으로 맞춰야 함
                "cron:amd64": ["/usr/bin/crontab"], "coreutils": ["/bin/ls"]}
        check, f = self.scan(files, modes, dpkg, usrmerge)
        self.assertEqual([x.severity for x in f], ["critical", "critical"])
        taskset, xxd = f
        self.assertIn("SUID(root)/SGID(root) 파일 /usr/bin/taskset", taskset.reason)
        self.assertIn("셸 탈출·파일 읽기쓰기가 되는 프로그램", taskset.reason)
        self.assertNotIn("패키지에도 속하지 않는다", taskset.reason)
        details = [e.detail for e in xxd.evidence]
        self.assertEqual(details[0], "권한 -rwsr-x--- root:root — 그룹 root 구성원만 실행 가능")
        self.assertEqual(details[1], "패키지: xxd")
        self.assertTrue(details[4].startswith("속성 변경(ctime, SUID를 붙이면 바뀜): "))
        # 파일 수 = 실행 파일 6 + /etc/passwd·/etc/group 2 + dpkg 목록 6
        self.assertEqual(check.scope, "파일 14개 중 SUID·SGID 5개 (패키지 소속 5개)")

    @files_owned_by_root
    def test_shell_copy_backdoor(self):
        files = {"/bin/bash": "BASH-BINARY", "/var/tmp/.b": "BASH-BINARY"}
        _, f = self.scan(files, {"/bin/bash": 0o755, "/var/tmp/.b": 0o4755})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        for part in ("사용자가 쓸 수 있는 영역에 있다", "숨김 경로에 있다", "셸을 복사한 파일이다 (/bin/bash와 내용이 같음)"):
            self.assertIn(part, f[0].reason)
        self.assertIn("패키지: 확인 불가 (dpkg 정보 없음)", [e.detail for e in f[0].evidence])

    @files_owned_by_root
    def test_unpackaged_and_sgid_only(self):
        files = {"/usr/local/bin/helper": ELF.format(1), "/usr/bin/sort": ELF.format(2)}
        _, f = self.scan(files, {"/usr/local/bin/helper": 0o4755, "/usr/bin/sort": 0o2755},
                         dpkg={"coreutils": ["/usr/bin/sort"]})
        sev = {x.reason.split(" 파일 ")[1].split(":")[0]: x.severity for x in f}
        self.assertEqual(sev, {"/usr/local/bin/helper": "warning",   # 패키지 밖
                               "/usr/bin/sort": "warning"})          # 그룹 SUID만 — 그룹 권한까지
        helper = [x for x in f if "helper" in x.reason][0]
        self.assertIn("어떤 패키지에도 속하지 않는다", helper.reason)

    @files_owned_by_root
    def test_excluded_areas_and_dev_shm(self):
        files = {"/proc/1/x": "x", "/sys/x": "x", "/run/x": "x", "/snap/core/1/usr/bin/sudo": "x",
                 "/dev/fake": "x", "/dev/shm/.x/run": "x", "/mnt/nfs/tool": "x",
                 "/proc/mounts": "/dev/sda1 / ext4 rw 0 0\nsrv:/export /mnt/nfs nfs4 rw 0 0\n"}
        modes = {p: 0o4755 for p in files if p != "/proc/mounts"}
        _, f = self.scan(files, modes)
        self.assertEqual([x.reason.split(" 파일 ")[1].split(":")[0] for x in f], ["/dev/shm/.x/run"])

    @files_owned_by_root
    def test_clean_system(self):
        check, f = self.scan({"/usr/bin/passwd": ELF.format(1)}, {"/usr/bin/passwd": 0o4755},
                             dpkg={"passwd": ["/usr/bin/passwd"]})
        self.assertEqual(f, [])
        # 파일 수 = passwd 실행 파일 + /etc/passwd·/etc/group + dpkg 목록
        self.assertEqual(check.scope, "파일 4개 중 SUID·SGID 1개 (패키지 소속 1개)")

    def test_symlinks_are_not_followed(self):
        def link(root):
            os.symlink("/usr/bin", os.path.join(root, "opt", "loop"))
        _, f = self.scan({"/opt/readme": "x"}, {}, extra_setup=link)
        self.assertEqual(f, [])

    def test_unreadable_dir_as_non_root(self):
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")

        def lock(root):
            os.chmod(os.path.join(root, "secret"), 0o000)
            self.addCleanup(os.chmod, os.path.join(root, "secret"), 0o755)
        with self.assertRaises(Unavailable):
            self.scan({"/secret/x": "x"}, {}, extra_setup=lock)


if __name__ == "__main__":
    unittest.main()
