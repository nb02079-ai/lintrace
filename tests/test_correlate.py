"""시간 상관분석: 정렬·활동 구간 묶기·미래 시각·시각 미상 분리·ctime·/proc 제외·HTML 이스케이프."""
import os
import unittest

from helpers import FakeRootTest

from lintrace import correlate as C
from lintrace.checks.base import Context, Evidence, Finding
from lintrace.report import html, json_report, text

NOW = 1_762_700_000


def F(cid, sev, ts=None, evidence=(), title="t", reason="r"):
    return Finding(cid, title, sev, "T1", reason, "s", list(evidence), ts)


class TestEvents(unittest.TestCase):
    def ctx(self):
        return Context("/", now=NOW)

    def test_order_and_grouping(self):
        # 두 사건은 5분 이내(한 구간), 세 번째는 한참 뒤(새 구간)
        fs = [F("ACC-09", "info", ts=NOW - 10000 + 0),
              F("ACC-08", "critical", ts=NOW - 10000 + 120),
              F("PRC-08", "critical", ts=NOW - 10000 + 5000)]
        b = C.build_block(self.ctx(), fs)
        self.assertEqual(b["counts"]["groups"], 2)
        self.assertEqual(len(b["groups"][0]["events"]), 2)
        self.assertEqual(len(b["groups"][1]["events"]), 1)
        # 시간 순
        t0 = b["groups"][0]["events"][0]["time_str"]
        t1 = b["groups"][0]["events"][1]["time_str"]
        self.assertLess(t0, t1)

    def test_future_flagged(self):
        fs = [F("ACC-09", "info", ts=NOW - 100),
              F("LOG-06", "warning", ts=NOW + 10 * 86400)]  # 미래
        b = C.build_block(self.ctx(), fs)
        fut_events = [e for g in b["groups"] for e in g["events"] if e["future"]]
        self.assertEqual(len(fut_events), 1)
        self.assertTrue(any(g["future"] for g in b["groups"]))

    def test_unknown_separated(self):
        # 시각도 없고 파일 근거도 없는 탐지 → 시각 미상
        fs = [F("ACC-09", "info", ts=NOW - 100), F("ACC-09", "info", ts=NOW - 50),
              F("NET-01", "warning", evidence=[Evidence("/proc/net/tcp", "x")])]
        b = C.build_block(self.ctx(), fs)
        self.assertEqual([u["check_id"] for u in b["unknown"]], ["NET-01"])

    def test_proc_excluded(self):
        fs = [F("PRC-02", "critical", evidence=[Evidence("/proc/67/comm", "x")]),
              F("ACC-09", "info", ts=NOW - 100), F("ACC-08", "critical", ts=NOW - 90)]
        b = C.build_block(self.ctx(), fs)
        # /proc 근거는 이벤트가 안 되고 PRC-02는 시각 미상
        self.assertIn("PRC-02", [u["check_id"] for u in b["unknown"]])

    def test_too_few_events_none(self):
        self.assertIsNone(C.build_block(self.ctx(), [F("ACC-09", "info", ts=NOW)]))


class TestFileTimes(FakeRootTest):
    def test_ctime_event_and_mtime_shown(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "/evil": "x"})
        p = os.path.join(root, "evil")
        past = NOW - 50000
        os.utime(p, (past, past))   # mtime 과거로 (ctime은 지금)
        ctx = Context(root, now=NOW)
        fs = [F("FS-05", "warning", evidence=[Evidence("/evil", "패키지 밖")]),
              F("ACC-09", "info", ts=NOW)]
        b = C.build_block(ctx, fs)
        evs = [e for g in b["groups"] for e in g["events"]]
        fe = [e for e in evs if "/evil" in e["detail"]][0]
        self.assertIn("ctime", fe["detail"])
        self.assertIn("내용(mtime)", fe["detail"])   # mtime이 달라 보조 표시


class TestReport(FakeRootTest):
    def block(self):
        ctx = Context("/", now=NOW)
        fs = [F("ACC-09", "info", ts=NOW - 200), F("ACC-08", "critical", ts=NOW - 100,
                                                   title='a"b', reason="<script>x</script>")]
        return ctx, fs

    def test_text_section(self):
        ctx, fs = self.block()
        out = text.render(fs, [], [], {}, [], timeline=C.build_block(ctx, fs))
        self.assertIn("사건 타임라인", out)
        self.assertIn("단서일 뿐", out)

    def test_html_escapes(self):
        ctx, fs = self.block()
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        report = json_report.build(Context(root, now=NOW), [], [], [], {}, [], "s",
                                   timeline=C.build_block(ctx, fs))
        out = html.render(report)
        self.assertIn("사건 타임라인", out)
        self.assertNotIn("<script>x", out)
        self.assertIn("&lt;script&gt;x", out)


if __name__ == "__main__":
    unittest.main()
