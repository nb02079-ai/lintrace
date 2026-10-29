import os
import unittest

from lintrace.checks.acc_01 import Acc01
from lintrace.checks.base import Context

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class TestAcc01(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(Acc01().run(Context(os.path.join(FIX, "clean"))), [])

    def test_hit(self):
        f = Acc01().run(Context(os.path.join(FIX, "acc_01_hit")))
        self.assertEqual(len(f), 1)
        self.assertIn("backup2", f[0].reason)
        self.assertEqual(f[0].evidence[0].source, "/etc/passwd")


if __name__ == "__main__":
    unittest.main()
