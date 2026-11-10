"""기준선 비교: 사실 수집 결정성, diff(추가·삭제·변경), 머신 불일치, 민감정보 미저장, 리포트 통합."""
import json
import unittest

from helpers import FakeRootTest

from lintrace import baseline as B
from lintrace.checks.base import Context
from lintrace.report import html, json_report, text

NOW = 1_762_700_000
PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "deploy:x:1001:1001::/home/deploy:/bin/bash\n"
          "www-data:x:33:33::/var/www:/usr/sbin/nologin\n")
SHADOW = "root:$6$abc$REALHASHVALUE:19000:0:99999:7:::\ndeploy:!:19000:0:99999:7:::\n"
GROUP = "root:x:0:\nsudo:x:27:deploy\ndocker:x:998:deploy\n"


def fake_facts(**over):
    base = {"listen": ["tcp|22|/usr/sbin/sshd"], "account": ["root|uid=0"], "group": ["sudo|deploy"],
            "module": ["nfsd"], "firewall": "FW", "suid": {"/usr/bin/sudo": "h1"},
            "unpackaged": {}, "config": {"/etc/ssh/sshd_config": "c1"}, "persistence": {"/etc/rc.local": "p1"}}
    base.update(over)
    return {"schema": 1, "host": "web01", "kernel": "6.8", "os": "Ubuntu 24.04",
            "tool": {"code_sha256": "abc"}, "created": "2026-11-09T00:00:00+00:00", "facts": base}


class TestSnapshot(FakeRootTest):
    def ctx(self):
        root = self.make_root({"/etc/passwd": PASSWD, "/etc/group": GROUP, "/etc/shadow": SHADOW,
                               "/etc/ssh/sshd_config": "PermitRootLogin no\n", "/etc/hostname": "web01\n",
                               "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04"\n'})
        return Context(root, now=NOW)

    def test_deterministic(self):
        s1 = B.snapshot(self.ctx(), with_packages=False)
        s2 = B.snapshot(self.ctx(), with_packages=False)
        self.assertEqual(s1["facts"], s2["facts"])

    def test_accounts_and_groups(self):
        f = B.snapshot(self.ctx(), with_packages=False)["facts"]
        self.assertTrue(any(a.startswith("deploy|uid=1001|") for a in f["account"]))
        self.assertIn("sudo|deploy", f["group"])
        self.assertIn("docker|deploy", f["group"])

    def test_no_password_hash_stored(self):
        blob = json.dumps(B.snapshot(self.ctx(), with_packages=False), ensure_ascii=False)
        self.assertNotIn("REALHASHVALUE", blob)   # 해시값은 저장 안 함
        self.assertIn("pw=set", blob)              # 상태만
        self.assertIn("pw=locked", blob)           # deploy는 ! → locked

    def test_header_fields(self):
        s = B.snapshot(self.ctx(), with_packages=False)
        self.assertEqual(s["host"], "web01")
        self.assertEqual(s["os"], "Ubuntu 24.04")
        self.assertEqual(s["schema"], B.SCHEMA)


class TestCompare(unittest.TestCase):
    def test_added_removed_changed(self):
        base = fake_facts()
        cur = fake_facts(listen=["tcp|22|/usr/sbin/sshd", "tcp|4444|/tmp/.x/nc"],
                         config={"/etc/ssh/sshd_config": "CHANGED"},
                         suid={})
        ch = {(c.category, c.kind): c for c in B.compare(base, cur)}
        self.assertIn(("listen", "added"), ch)
        self.assertIn("4444", ch[("listen", "added")].key)
        self.assertIn(("config", "changed"), ch)
        self.assertIn(("suid", "removed"), ch)

    def test_no_change(self):
        self.assertEqual(B.compare(fake_facts(), fake_facts()), [])

    def test_firewall_change(self):
        ch = B.compare(fake_facts(), fake_facts(firewall="DIFFERENT"))
        self.assertEqual([(c.category, c.kind) for c in ch], [("firewall", "changed")])


class TestMismatch(FakeRootTest):
    def test_detects_different_machine(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                               "/etc/hostname": "db02\n", "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04"\n'})
        ctx = Context(root, now=NOW)
        m = B.mismatch(fake_facts(), ctx)
        self.assertIsNotNone(m)
        self.assertIn("호스트", m)
        self.assertIn("OS", m)

    def test_same_machine_none(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                               "/etc/hostname": "web01\n", "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04"\n'})
        ctx = Context(root, now=NOW)
        base = fake_facts()
        base["kernel"] = None  # 가짜 루트는 커널을 안 넣으므로 커널 비교 생략
        self.assertIsNone(B.mismatch(base, ctx))


class TestReportIntegration(FakeRootTest):
    def block(self, base, cur):
        changes = B.compare(base, cur)
        return B.report_block(base, changes, None)

    def test_verdict_bumps_on_added(self):
        # 점검 탐지는 없지만 기준선에 새로 생긴 것이 있으면 정상 → 위험
        blk = self.block(fake_facts(), fake_facts(listen=["tcp|22|/usr/sbin/sshd", "tcp|4444|/x"]))
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        ctx = Context(root, now=NOW)
        report = json_report.build(ctx, [], [], [], {}, [], "s", baseline=blk)
        self.assertEqual(report["verdict"], "warning")
        self.assertIn("baseline", report)

    def test_removed_only_stays_clean(self):
        blk = self.block(fake_facts(), fake_facts(suid={}))   # 사라짐만
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        report = json_report.build(Context(root, now=NOW), [], [], [], {}, [], "s", baseline=blk)
        self.assertEqual(report["verdict"], "clean")

    def test_html_escapes_change_path(self):
        cur = fake_facts(config={"/etc/ssh/sshd_config": "c1", "/tmp/<script>x": "h"})
        blk = self.block(fake_facts(), cur)
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        report = json_report.build(Context(root, now=NOW), [], [], [], {}, [], "s", baseline=blk)
        out = html.render(report)
        self.assertIn("기준선과 달라진 점", out)
        self.assertNotIn("<script>x", out)
        self.assertIn("&lt;script&gt;x", out)

    def test_text_section(self):
        blk = self.block(fake_facts(), fake_facts(listen=["tcp|22|/usr/sbin/sshd", "tcp|4444|/x"]))
        out = text.render([], [], [], {}, [], baseline=blk)
        self.assertIn("기준선과 달라진 점", out)
        self.assertIn("침해된 뒤 찍혔다면", out)
        self.assertIn("4444", out)


if __name__ == "__main__":
    unittest.main()
