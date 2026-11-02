import os
import time
import unittest

from lintrace import timefmt

NOW = 1793600000.0  # 고정 기준 시각


class TestTimefmt(unittest.TestCase):
    def setUp(self):
        self.old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"
        time.tzset()

    def tearDown(self):
        if self.old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.old_tz
        time.tzset()

    def test_span(self):
        self.assertEqual(timefmt.span(30), "30초")
        self.assertEqual(timefmt.span(5 * 60), "5분")
        self.assertEqual(timefmt.span(2 * 3600), "2시간")
        self.assertEqual(timefmt.span(3 * 86400), "3일")
        self.assertEqual(timefmt.span(65 * 86400), "약 2개월")
        self.assertEqual(timefmt.span(8 * 365 * 86400), "약 8년")

    def test_past(self):
        text, future = timefmt.describe(NOW - 3 * 86400, NOW)
        self.assertFalse(future)
        self.assertTrue(text.startswith("3일 전 ("))
        self.assertTrue(text.endswith("+0000)"))

    def test_future(self):
        text, future = timefmt.describe(NOW + 2 * 86400, NOW)
        self.assertTrue(future)
        self.assertIn("미래 시각", text)

    def test_small_clock_skew_is_not_future(self):
        text, future = timefmt.describe(NOW + 30, NOW)
        self.assertFalse(future)
        self.assertTrue(text.startswith("0초 전"))


if __name__ == "__main__":
    unittest.main()
