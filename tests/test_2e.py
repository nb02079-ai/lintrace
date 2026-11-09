"""2-E 로그 계열: LOG-02·03·04·05·06·07, journal·utmp 수집기, ACC-08·09 journal 보충."""
import os
import struct
import time
import unittest

from helpers import FakeRootTest

from lintrace.checks.base import Context
from lintrace.checks.log_02 import Log02
from lintrace.checks.log_03 import Log03
from lintrace.checks.log_04 import Log04
from lintrace.checks.log_05 import Log05
from lintrace.checks.log_06 import Log06
from lintrace.checks.log_07 import Log07
from lintrace.collectors.filewalk import Walk
from lintrace.collectors.journal import Journal, Record, parse
from lintrace.collectors.utmp import LOGIN, parse as utmp_parse

NOW = 1_762_700_000


def rec(ts, prog="x", msg="", mono=None, boot="b1", pri=6):
    return Record(boot, ts, mono, prog, msg, pri)


def wtmp_bytes(entries):
    """entries: [(type, user, line, host, ts)] → wtmp 바이트."""
    out = bytearray()
    for t, user, line, host, ts in entries:
        r = bytearray(384)
        struct.pack_into("<h2xi32s4s32s256s", r, 0, t, 0, line.encode(), b"", user.encode(), host.encode())
        struct.pack_into("<i", r, 340, ts)
        out += r
    return bytes(out)


def auth_line(ts, msg):
    t = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))
    return "{} host sshd[111]: {}".format(t, msg)


class Base(FakeRootTest):
    def ctx(self, files):
        files = dict(files)
        files.setdefault("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntest:x:1000:1000::/home/test:/bin/bash\n")
        return Context(self.make_root(files), now=NOW)

    def run_check(self, cls, files, journal=None, walk=None):
        ctx = self.ctx(files)
        if journal is not None:
            ctx._journal = journal
        if walk is not None:
            ctx._filewalk = walk
        c = cls()
        return c, c.run(ctx)


class TestCollectors(unittest.TestCase):
    def test_journal_parse(self):
        line = ('{"__REALTIME_TIMESTAMP":"1762700000000000","__MONOTONIC_TIMESTAMP":"5000000",'
                '"_BOOT_ID":"abc","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Accepted password for test"}')
        r = parse(line)[0]
        self.assertEqual((r.realtime, r.monotonic, r.prog, r.boot), (1762700000.0, 5.0, "sshd", "abc"))

    def test_journal_binary_message(self):
        line = '{"__REALTIME_TIMESTAMP":"1762700000000000","MESSAGE":[104,105]}'  # "hi"
        self.assertEqual(parse(line)[0].msg, "hi")

    def test_utmp_parse(self):
        data = wtmp_bytes([(LOGIN, "test", "pts/0", "10.0.0.9", 1762700000)])
        logins, ok = utmp_parse(data)
        self.assertTrue(ok)
        self.assertEqual((logins[0].user, logins[0].host, logins[0].ts), ("test", "10.0.0.9", 1762700000))


class TestLog02(Base):
    def test_missing_login_is_critical(self):
        # auth.log에 로그인 성공이 있는데 wtmp에는 그 세션이 없다
        files = {"/var/log/auth.log": auth_line(NOW - 100, "Accepted password for test from 10.0.0.9 port 2") + "\n",
                 "/var/log/wtmp": wtmp_bytes([(2, "reboot", "~", "", NOW - 500)])}  # 부팅만, 로그인 없음
        c, f = self.run_check(Log02, files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("SSH 로그인 성공 1건", f[0].reason)

    def test_matching_login_is_clean(self):
        files = {"/var/log/auth.log": auth_line(NOW - 100, "Accepted password for test from 10.0.0.9 port 2") + "\n",
                 "/var/log/wtmp": wtmp_bytes([(2, "reboot", "~", "", NOW - 500),
                                              (LOGIN, "test", "pts/0", "10.0.0.9", NOW - 100)])}
        c, f = self.run_check(Log02, files)
        self.assertEqual(f, [])

    def test_login_before_wtmp_start_ignored(self):
        # wtmp가 그 로그인 이후부터 시작 → 순환으로 지워진 기간, 불일치 아님
        files = {"/var/log/auth.log": auth_line(NOW - 10000, "Accepted password for test from 10.0.0.9 port 2") + "\n",
                 "/var/log/wtmp": wtmp_bytes([(LOGIN, "test", "pts/0", "10.0.0.9", NOW - 100)])}
        c, f = self.run_check(Log02, files)
        self.assertEqual(f, [])

    def test_misaligned_size_is_warning(self):
        files = {"/var/log/wtmp": wtmp_bytes([(LOGIN, "t", "pts/0", "h", NOW)]) + b"\x00\x05"}
        c, f = self.run_check(Log02, files)
        self.assertEqual([x.severity for x in f], ["warning"])
        self.assertIn("배수가 아니다", f[0].reason)


class TestLog03(Base):
    def test_devnull_link(self):
        root = self.make_root({"/etc/passwd": "test:x:1000:1000::/home/test:/bin/bash\n"})
        os.makedirs(os.path.join(root, "home/test"))
        os.symlink("/dev/null", os.path.join(root, "home/test/.bash_history"))
        c = Log03()
        f = c.run(Context(root, now=NOW))
        self.assertEqual(len(f), 1)
        self.assertIn("/dev/null", f[0].reason)

    def test_empty_history(self):
        c, f = self.run_check(Log03, {"/home/test/.bash_history": ""})
        self.assertEqual([x.severity for x in f], ["warning"])
        self.assertIn("0바이트", f[0].reason)

    def test_nologin_empty_is_clean(self):
        files = {"/etc/passwd": "www-data:x:33:33::/var/www:/usr/sbin/nologin\n", "/var/www/.bash_history": ""}
        c, f = self.run_check(Log03, files)
        self.assertEqual(f, [])


class TestLog04(Base):
    def test_masked(self):
        root = self.make_root({"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        os.makedirs(os.path.join(root, "etc/systemd/system"))
        os.symlink("/dev/null", os.path.join(root, "etc/systemd/system/rsyslog.service"))
        c = Log04()
        f = c.run(Context(root, now=NOW))
        self.assertTrue(any("마스크" in x.reason for x in f))
        self.assertTrue(any(x.severity == "critical" for x in f))

    def test_storage_none(self):
        c, f = self.run_check(Log04, {"/etc/systemd/journald.conf": "[Journal]\nStorage=none\n"})
        warn = [x for x in f if "디스크에 저장" in x.reason]
        self.assertEqual(len(warn), 1)
        self.assertEqual(warn[0].severity, "warning")


class TestLog05(Base):
    def journal(self, gaps, near_login=False):
        recs = [rec(NOW, "systemd", "start", mono=0)]
        t = 0
        for g in gaps:
            if near_login:
                recs.append(rec(NOW + t, "sshd", "Accepted password for test", mono=t))
            t += g
            recs.append(rec(NOW + t, "cron", "job", mono=t))
        return Journal(recs, True)

    CRON = {"/etc/cron.hourly/std": "#!/bin/sh\n"}

    def test_long_gap_warning(self):
        c, f = self.run_check(Log05, self.CRON, journal=self.journal([3 * 3600]))
        self.assertEqual([x.severity for x in f], ["warning"])
        self.assertIn("시간 동안 아무 기록이 없다", f[0].reason)

    def test_gap_with_login_is_critical(self):
        c, f = self.run_check(Log05, self.CRON, journal=self.journal([3 * 3600], near_login=True))
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("로그인·sudo 기록이 있다", f[0].reason)

    def test_short_gap_clean(self):
        c, f = self.run_check(Log05, self.CRON, journal=self.journal([600, 600]))
        self.assertEqual(f, [])
        self.assertIn("최대 공백", c.scope)


class TestLog06(Base):
    def test_clock_backward(self):
        # 단조는 늘었는데 실시간이 10분 뒤로
        recs = [rec(NOW, mono=0), rec(NOW + 10, mono=10), rec(NOW - 600, mono=20)]
        c, f = self.run_check(Log06, {}, journal=Journal(recs, True), walk=Walk())
        self.assertEqual(len(f), 1)
        self.assertIn("뒤로 돌아갔다", f[0].reason)

    def test_future_file(self):
        root = self.make_root({"/etc/x": "a"})
        future = os.path.join(root, "usr/bin/evil")
        os.makedirs(os.path.dirname(future))
        open(future, "w").close()
        ft = NOW + 5 * 86400
        os.utime(future, (ft, ft))
        w = Walk()
        w.future = [("/usr/bin/evil", os.lstat(future))]
        ctx = Context(root, now=NOW)
        ctx._filewalk = w
        ctx._journal = Journal([], False)
        c = Log06()
        f = c.run(ctx)
        self.assertEqual(len(f), 1)
        self.assertIn("미래인 파일 1개", f[0].reason)


class TestLog07(Base):
    def test_network_oops(self):
        recs = [rec(NOW, "kernel", "BUG: unable to handle kernel NULL pointer dereference", mono=1),
                rec(NOW + 1, "kernel", "Call Trace:", mono=2),
                rec(NOW + 1, "kernel", " tcp_v4_rcv+0x1a/0x2b", mono=2),
                rec(NOW + 2, "kernel", "general protection fault in vmwgfx_do_thing", mono=3)]
        c, f = self.run_check(Log07, {}, journal=Journal(recs, True))
        net = [x for x in f if "네트워크 코드" in x.reason]
        self.assertEqual(net[0].severity, "warning")
        other = [x for x in f if "네트워크 외" in x.reason]
        self.assertEqual(other[0].severity, "info")

    def test_benign_kernel_messages_clean(self):
        recs = [rec(NOW, "kernel", "RETBleed: WARNING: Spectre v2 mitigation leaves CPU vulnerable", mono=1),
                rec(NOW + 1, "kernel", "vmwgfx 0000:00:02.0: [drm] *ERROR* unsupported hypervisor", mono=2)]
        c, f = self.run_check(Log07, {}, journal=Journal(recs, True))
        self.assertEqual(f, [])


class TestAcc0809Journal(Base):
    def test_journal_supplements_missing_authlog(self):
        from lintrace.collectors.authlog import auth_log
        # auth.log 없음, journal에 sshd 성공 3건
        recs = [rec(NOW + i, "sshd", "Accepted password for test from 10.0.0.{} port 2".format(i), mono=i)
                for i in range(3)]
        ctx = self.ctx({})
        ctx._journal = Journal(recs, True)
        log = auth_log(ctx)
        self.assertTrue(log.available)
        self.assertEqual(len(log.sshd()), 3)
        self.assertIn("journal sshd 기록 3건", log.scope())


if __name__ == "__main__":
    unittest.main()
