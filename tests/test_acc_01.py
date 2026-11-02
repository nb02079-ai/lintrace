import os
import unittest

from lintrace.checks.acc_01 import Acc01, mask_passwd_line
from lintrace.checks.base import Context, Unavailable

from helpers import FakeRootTest

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class TestAcc01(FakeRootTest):
    def test_clean(self):
        self.assertEqual(Acc01().run(Context(os.path.join(FIX, "clean"))), [])

    def test_hit(self):
        f = Acc01().run(Context(os.path.join(FIX, "acc_01_hit")))
        self.assertEqual(len(f), 1)
        self.assertIn("backup2", f[0].reason)
        self.assertEqual(f[0].evidence[0].source, "/etc/passwd")
        self.assertIn("backup2:x:0:0", f[0].evidence[0].detail)  # 'x'는 가리지 않는다

    def test_hash_is_masked(self):
        # lin.security의 insecurity 계정처럼 passwd에 해시가 직접 들어 있는 경우
        root = self.make_root({"/etc/passwd":
                               "root:x:0:0:root:/root:/bin/bash\n"
                               "insecurity:AzER3pBZh6WZE:0:0::/:/bin/sh\n"})
        f = Acc01().run(Context(root))
        self.assertEqual(len(f), 1)
        self.assertNotIn("AzER3pBZh6WZE", f[0].evidence[0].detail)
        self.assertIn("insecurity:<가림>:0:0::/:/bin/sh", f[0].evidence[0].detail)

    def test_mask_keeps_non_secret_values(self):
        for value in ("x", "*", "!", "!!", ""):
            line = "u:{}:0:0::/:/bin/sh".format(value)
            self.assertEqual(mask_passwd_line(line), line)

    def test_missing_passwd_is_unavailable(self):
        root = self.make_root({"/etc": None})
        with self.assertRaises(Unavailable):
            Acc01().run(Context(root))


if __name__ == "__main__":
    unittest.main()
