import os
import unittest

from lintrace.checks.base import Context, Unavailable
from lintrace.checks.per_05 import Per05, odd_location, preload_entries

from helpers import FakeRootTest, files_owned_by_root

NOW = 1793600000.0

# lin.security(Ubuntu 18.04)의 설정 그대로
LD_CONF = "include /etc/ld.so.conf.d/*.conf\n\n"
LIBC_CONF = "# libc default configuration\n/usr/local/lib\n"
X86_CONF = ("# Multiarch support\n/usr/local/lib/x86_64-linux-gnu\n"
            "/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n")
LIB_DIRS = ["/usr/local/lib", "/usr/local/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"]


class TestHelpers(unittest.TestCase):
    def test_preload_entries(self):
        self.assertEqual(preload_entries(["/a.so:/b.so /c.so", "# 주석", "", "/d.so # 뒤 주석"]),
                         [(1, "/a.so"), (1, "/b.so"), (1, "/c.so"), (4, "/d.so")])

    def test_odd_location(self):
        self.assertEqual(odd_location("/tmp/.x/lib.so"), "임시 폴더")
        self.assertEqual(odd_location("/usr/lib/.cache/libx.so"), "숨김 경로")
        self.assertIsNone(odd_location("/lib/x86_64-linux-gnu/libdl.so.2"))


class TestPer05(FakeRootTest):
    def scan(self, files, modes=None):
        base = {"/etc/ld.so.conf": LD_CONF,
                "/etc/ld.so.conf.d/libc.conf": LIBC_CONF,
                "/etc/ld.so.conf.d/x86_64-linux-gnu.conf": X86_CONF}
        for d in LIB_DIRS:
            base[d] = None
        base.update(files)
        root = self.make_root(base)
        all_modes = {d: 0o755 for d in LIB_DIRS}
        all_modes.update(modes or {})
        for path, mode in all_modes.items():
            os.chmod(os.path.join(root, path.lstrip("/")), mode)
        check = Per05()
        return root, check, check.run(Context(root, now=NOW))

    @files_owned_by_root
    def test_linsecurity_is_clean(self):
        _, check, f = self.scan({})
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "preload 없음, 라이브러리 경로 4개")

    @files_owned_by_root
    def test_preload_with_real_library_is_critical(self):
        lib = "/lib/x86_64-linux-gnu/libdl.so.2"
        _, check, f = self.scan({"/etc/ld.so.preload": lib + "\n", lib: "\x7fELF"},
                                modes={"/etc/ld.so.preload": 0o644})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("라이브러리 1개가 강제로 불려 들어간다", f[0].reason)
        self.assertIn("1행: {} (있음, 권한".format(lib), f[0].evidence[0].detail)
        self.assertTrue(f[0].evidence[-1].detail.startswith("파일 변경: "))
        self.assertEqual(check.scope, "preload 라이브러리 1개, 라이브러리 경로 4개")

    @files_owned_by_root
    def test_preload_from_hidden_temp_dir(self):
        _, _, f = self.scan({"/etc/ld.so.preload": "/tmp/.x/libhide.so\n/usr/lib/.c/liby.so\n"},
                            modes={"/etc/ld.so.preload": 0o644})
        self.assertIn("임시 폴더: /tmp/.x/libhide.so", f[0].reason)
        self.assertIn("숨김 경로: /usr/lib/.c/liby.so", f[0].reason)
        self.assertIn("(파일 없음)", f[0].evidence[0].detail)

    @files_owned_by_root
    def test_empty_preload_is_info(self):
        _, _, f = self.scan({"/etc/ld.so.preload": "# nothing\n"}, modes={"/etc/ld.so.preload": 0o644})
        self.assertEqual(f[0].severity, "info")
        self.assertIn("적힌 라이브러리가 없다", f[0].reason)

    @files_owned_by_root
    def test_writable_empty_preload_is_warning(self):
        _, _, f = self.scan({"/etc/ld.so.preload": ""}, modes={"/etc/ld.so.preload": 0o666})
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("다른 사용자가 바꿀 수 있다 (권한 666", f[0].reason)

    @files_owned_by_root
    def test_lib_dir_in_user_area_or_writable(self):
        _, _, f = self.scan({"/etc/ld.so.conf.d/zz-app.conf": "/opt/app/lib\n/home/bob/lib\n/srv/missing\n",
                             "/opt/app/lib": None, "/home/bob/lib": None},
                            modes={"/opt/app/lib": 0o777, "/home/bob/lib": 0o755})
        reasons = sorted(x.reason for x in f)
        self.assertEqual(len(f), 2, reasons)  # 없는 폴더(/srv/missing)는 건너뜀
        self.assertTrue(all(x.severity == "warning" for x in f))
        self.assertTrue(any("/home/bob/lib: 사용자 영역" in r for r in reasons))
        self.assertTrue(any("/opt/app/lib: 다른 사용자가 쓸 수 있다 (권한 777" in r for r in reasons))
        bob = [x for x in f if "/home/bob/lib" in x.reason][0]
        self.assertEqual((bob.evidence[0].source, bob.evidence[0].detail),
                         ("/etc/ld.so.conf.d/zz-app.conf", "2행: /home/bob/lib"))

    @files_owned_by_root
    def test_writable_conf_file(self):
        _, _, f = self.scan({}, modes={"/etc/ld.so.conf.d/libc.conf": 0o666})
        self.assertEqual(len(f), 1)
        self.assertIn("라이브러리 경로 설정 /etc/ld.so.conf.d/libc.conf", f[0].reason)

    @files_owned_by_root
    def test_include_skips_non_conf(self):
        _, check, f = self.scan({"/etc/ld.so.conf.d/old.conf.bak": "/tmp\n"})
        self.assertEqual(f, [])  # '*.conf'에 맞지 않는 파일은 읽지 않는다
        self.assertEqual(check.scope, "preload 없음, 라이브러리 경로 4개")

    def test_non_root_owned_preload_is_flagged(self):
        if os.geteuid() == 0:
            self.skipTest("일반 계정 소유 파일을 만들려면 일반 계정으로 실행해야 함")
        _, _, f = self.scan({"/etc/ld.so.preload": ""}, modes={"/etc/ld.so.preload": 0o644})
        self.assertEqual(f[0].severity, "warning")  # root 소유가 아닌 preload

    def test_fifo_preload_is_unavailable(self):
        root = self.make_root({"/etc": None})
        os.mkfifo(os.path.join(root, "etc", "ld.so.preload"), 0o600)
        with self.assertRaises(Unavailable):
            Per05().run(Context(root, now=NOW))  # 멈추면 실패


if __name__ == "__main__":
    unittest.main()
