"""실행기와 리포트, 그리고 항목 목록(catalog)과 구현의 일치를 확인한다."""
import io
import json
import os
import unittest
from contextlib import redirect_stdout

from lintrace.__main__ import main, run_checks
from lintrace.checks import ALL_CHECKS
from lintrace.checks.base import Check, Context
from lintrace.report import text

from helpers import FakeRootTest

CATALOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "catalog.json")
SEVERITY = {"critical", "warning", "info"}


class Broken(Check):
    id, title, severity, attack = "TEST-99", "일부러 실패하는 항목", "warning", "T0000"

    def run(self, ctx):
        raise ValueError("버그")


class TestRunner(FakeRootTest):
    def output(self, root):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--root", root])
        return buf.getvalue()

    def test_unavailable_is_not_reported_as_clean(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                               "/etc/sudoers": None})  # 읽을 수 없는 sudoers
        out = self.output(root)
        self.assertIn("점검 불가 1개", out.splitlines()[0])
        self.assertIn("  ACC-06 — ", out)
        self.assertIn("이상 없음: ACC-01", out)
        self.assertNotIn("ACC-06", out.split("이상 없음:")[1])

    def test_one_broken_check_does_not_stop_others(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nb:x:0:0::/:/bin/sh\n"})
        findings, unavailable = run_checks(Context(root), [Broken] + list(ALL_CHECKS))
        self.assertEqual([f.check_id for f in findings], ["ACC-01"])
        self.assertEqual(unavailable[0][0], "TEST-99")
        self.assertIn("ValueError: 버그", unavailable[0][1])

    def test_clean_report_has_no_unavailable_section(self):
        out = text.render([], ["ACC-01"], [])
        self.assertTrue(out.startswith("전체 판정: 정상\n"))
        self.assertNotIn("점검 불가 (", out)


class TestCatalog(unittest.TestCase):
    def test_implemented_checks_match_catalog(self):
        with open(CATALOG, encoding="utf-8") as f:
            catalog = {c["id"]: c for c in json.load(f)}
        self.assertEqual(len(catalog), 52)
        ids = [c.id for c in ALL_CHECKS]
        self.assertEqual(len(ids), len(set(ids)), "같은 ID가 두 번 등록됨")
        for cls in ALL_CHECKS:
            entry = catalog[cls.id]
            self.assertEqual(cls.title, entry["name"], cls.id)
            self.assertEqual(cls.severity, entry["severity"], cls.id)
            self.assertEqual(cls.attack, entry["attack"], cls.id)
            self.assertEqual(entry["status"], "implemented", cls.id)
            self.assertIn(cls.severity, SEVERITY)
        for cid, entry in catalog.items():
            if entry["status"] == "implemented":
                self.assertIn(cid, ids, "catalog에는 구현으로 표시됐지만 등록되지 않음")


if __name__ == "__main__":
    unittest.main()
