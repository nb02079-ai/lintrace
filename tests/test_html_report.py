"""HTML 리포트: 공격자 문자열 이스케이프, 구조, CSP."""
import re
import unittest

from lintrace.report import html


def report(findings_items=None, verdict="critical", unavailable=None):
    """최소 build() 모양의 사전."""
    return {
        "schema": 1,
        "tool": {"name": "lintrace", "version": "0.1.0", "code_sha256": "abc123"},
        "run": {"host": "web01", "os": "Ubuntu 24.04", "kernel": "6.8.0", "root": "/", "euid": 0,
                "sudo_user": "test", "started": "2026-11-09T05:00:00+00:00", "finished": "2026-11-09T05:00:12+00:00"},
        "verdict": verdict, "incomplete": bool(unavailable),
        "counts": {"checks": 54, "findings": sum(len(i["findings"]) for i in (findings_items or [])),
                   "unavailable": len(unavailable or []), "critical": 1, "warning": 0, "info": 0},
        "report_warnings": [],
        "checks": (findings_items or []) + (unavailable or []),
    }


def item(cid, title, status="clean", findings=(), scope="범위", error=None):
    return {"id": cid, "title": title, "severity": "critical", "attack": "T1",
            "status": status, "scope": None if status == "unavailable" else scope,
            "findings": list(findings), "error": error}


def finding(severity="critical", reason="r", evidence=()):
    return {"severity": severity, "reason": reason, "next_steps": "s",
            "evidence": [{"source": s, "detail": d, "sha256": None} for s, d in evidence], "timestamp": None,
            "attack": "T1505.003"}


class TestEscaping(unittest.TestCase):
    def test_attacker_script_is_escaped(self):
        # 웹 로그·웹쉘의 공격자 문자열
        payload = '<script>alert(document.cookie)</script>'
        webshell = '<?php system($_GET["c"]); ?>'
        it = item("FS-06", "웹쉘", "detected",
                  [finding(reason="웹쉘 " + webshell, evidence=[("/var/log/nginx/access.log", payload)])])
        out = html.render(report([it]))
        # 실행 가능한 <script> 태그가 그대로 나오면 안 된다
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<?php system", out)
        # 이스케이프된 형태로는 들어 있어야 한다 (내용 보존)
        self.assertIn("&lt;script&gt;alert", out)
        self.assertIn("&lt;?php system", out)

    def test_path_with_angle_brackets(self):
        it = item("FS-05", "파일", "detected",
                  [finding(evidence=[("/tmp/<b>evil</b>", "x")])])
        out = html.render(report([it]))
        self.assertNotIn("<b>evil</b>", out)
        self.assertIn("&lt;b&gt;evil", out)

    def test_quotes_escaped_in_title(self):
        out = html.render(report([item('A"B', 'ti"tle', "clean")]))
        self.assertNotIn('ti"tle', out)


class TestStructure(unittest.TestCase):
    def test_has_csp_no_script_tag(self):
        out = html.render(report())
        self.assertIn('http-equiv="Content-Security-Policy"', out)
        self.assertIn("default-src 'none'", out)
        # 어떤 <script ...> 여는 태그도 없어야 한다
        self.assertFalse(re.search(r"<script[ >]", out), "리포트에 script 태그가 있으면 안 됨")

    def test_severity_order_and_open(self):
        items = [item("I1", "참고건", "detected", [finding("info")]),
                 item("C1", "심각건", "detected", [finding("critical")]),
                 item("W1", "위험건", "detected", [finding("warning")])]
        out = html.render(report(items))
        # 심각이 위험보다, 위험이 참고보다 먼저
        self.assertLess(out.index("심각건"), out.index("위험건"))
        self.assertLess(out.index("위험건"), out.index("참고건"))
        # 심각·위험은 펼침(open), 참고는 접힘
        crit = out[out.index('class="crit"'):]
        self.assertTrueDetailsOpen = self.assertIn('<details class="crit" open>', out)
        self.assertIn('<details class="warn" open>', out)
        self.assertIn('<details class="info">', out)

    def test_verdict_and_counts(self):
        out = html.render(report([item("C1", "x", "detected", [finding("critical")])], verdict="critical"))
        self.assertIn("전체 판정: 심각", out)
        self.assertIn("점검 54개", out)

    def test_unavailable_section(self):
        un = [item("ACC-06", "sudoers", "unavailable", error="권한 없음")]
        out = html.render(report([], verdict="clean", unavailable=un))
        self.assertIn("점검 불가", out)
        self.assertIn("권한 없음", out)
        self.assertIn("확정이 아닙니다", out)

    def test_clean_report(self):
        out = html.render(report([], verdict="clean"))
        self.assertIn("전체 판정: 정상", out)
        self.assertIn("탐지된 흔적이 없습니다", out)


if __name__ == "__main__":
    unittest.main()
