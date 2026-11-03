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

from helpers import FakeRootTest, files_owned_by_root

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
        summary = out.split("점검 범위:")[1]
        self.assertIn("  ACC-06 — 점검 불가\n", summary)
        self.assertIn("  ACC-01 — 계정 1개 확인 (이상 없음)", summary)

    def test_one_broken_check_does_not_stop_others(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nb:x:0:0::/:/bin/sh\n"})
        findings, unavailable, _, _ = run_checks(Context(root), [Broken] + list(ALL_CHECKS))
        self.assertEqual([f.check_id for f in findings], ["ACC-01"])
        self.assertEqual(unavailable[0][0], "TEST-99")
        self.assertIn("ValueError: 버그", unavailable[0][1])

    def test_fifo_in_place_of_file_does_not_hang(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        os.mkfifo(os.path.join(root, "etc", "sudoers"), 0o600)
        findings, unavailable, _, _ = run_checks(Context(root), list(ALL_CHECKS))  # 멈추면 실패
        self.assertEqual(findings, [])
        self.assertEqual(unavailable[0][0], "ACC-06")
        self.assertIn("일반 파일이 아님", unavailable[0][1])

    def test_report_warning_sits_right_under_verdict(self):
        out = text.render([], ["PER-05"], [], {}, ["경고 문장"])
        lines = out.splitlines()
        self.assertEqual(lines[0], "전체 판정: 정상")
        self.assertEqual(lines[1], "⚠ 경고 문장")
        self.assertTrue(lines[2].startswith("실행한 점검 "))

    def test_clean_report_has_no_unavailable_section(self):
        out = text.render([], ["ACC-01"], [])
        self.assertTrue(out.startswith("전체 판정: 정상\n"))
        self.assertNotIn("점검 불가 (", out)

    @files_owned_by_root
    def test_summary_shows_scope_of_every_check(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n"
                                              "x:x:0:0::/:/bin/sh\n",
                               "/root/.ssh/authorized_keys": ""})
        os.chmod(os.path.join(root, "root/.ssh/authorized_keys"), 0o600)
        os.chmod(os.path.join(root, "root/.ssh"), 0o700)
        out = self.output(root)
        summary = out.split("점검 범위:")[1]
        # 탐지가 있는 항목도 무엇을 보고 몇 건을 찾았는지 나온다
        self.assertIn("  ACC-01 — 계정 3개 확인 (탐지 1건)", summary)
        self.assertIn("  ACC-06 — sudo 미설치 (/etc/sudoers 없음) 확인 (이상 없음)", summary)
        self.assertIn("  ACC-07 — 키 파일 1개, 키 0개 확인 (이상 없음)", summary)  # lin.security의 빈 root 키 파일
        self.assertIn("  PER-01 — 예약 작업 0개, root가 실행하는 스크립트 0개 확인 (이상 없음)", summary)
        # 모든 등록 항목이 빠짐없이 한 줄씩 나온다
        lines = [l for l in summary.splitlines() if l.startswith("  ")]
        self.assertEqual([l.split(" — ")[0].strip() for l in lines], [c.id for c in ALL_CHECKS])
        self.assertTrue(out.rstrip().endswith(lines[-1]))  # 리포트의 맨 끝 구역


class TestCatalog(unittest.TestCase):
    def test_implemented_checks_match_catalog(self):
        with open(CATALOG, encoding="utf-8") as f:
            catalog = {c["id"]: c for c in json.load(f)}
        self.assertEqual(len(catalog), 54)  # PRC-09·LOG-07은 CVE-2026-98432를 계기로 추가한 2단계 후보
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
