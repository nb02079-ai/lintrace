import os
import unittest

from lintrace.checks.log_01 import Log01, rotated_base, rsyslog_targets, selector_kind
from lintrace.checks.base import Context

from helpers import FakeRootTest
from test_prc_01 import NOW, LinkContext, ProcRootTest, proc

# lin.security(18.04)와 Ubuntu 24.04에서 확인한 실제 설정과 같은 구성
RSYSLOG_CONF = """#  /etc/rsyslog.conf
module(load="imuxsock") # provides support for local system logging
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$IncludeConfig /etc/rsyslog.d/*.conf
"""
RSYSLOG_D = {
    "/etc/rsyslog.d/20-ufw.conf": '# Log kernel generated UFW log messages to file\n:msg,contains,"[UFW " /var/log/ufw.log\n& stop\n',
    "/etc/rsyslog.d/21-cloudinit.conf": ':syslogtag, isequal, "[CLOUDINIT]" /var/log/cloud-init.log\n& stop\n',
    "/etc/rsyslog.d/50-default.conf": (
        "#  Default rules for rsyslog.\n"
        "auth,authpriv.*                 /var/log/auth.log\n"
        "*.*;auth,authpriv.none          -/var/log/syslog\n"
        "#cron.*                         /var/log/cron.log\n"
        "kern.*                          -/var/log/kern.log\n"
        "mail.*                          -/var/log/mail.log\n"
        "mail.err                        /var/log/mail.err\n"
        "*.emerg                         :omusrmsg:*\n"),
}
NGINX_CONF = ("http {\n  access_log /var/log/nginx/access.log;\n  error_log /var/log/nginx/error.log;\n"
              "  include /etc/nginx/sites-enabled/*;\n}\n")
LINE = "Nov  3 03:02:25 linsecurity systemd-logind[600]: New seat seat0.\n"


def logs(**extra):
    files = {"/etc/rsyslog.conf": RSYSLOG_CONF, "/var/log/auth.log": LINE,
             "/var/log/syslog": LINE, "/var/log/kern.log": LINE}
    files.update(RSYSLOG_D)
    files.update(extra)
    return files


RSYSLOGD = proc(672, "rsyslogd", 104, 1, "/usr/sbin/rsyslogd -n -iNONE", "/usr/sbin/rsyslogd")
NGINX = proc(767, "nginx", 33, 766, "nginx: worker process", "/usr/sbin/nginx")
PHPFPM = proc(634, "php-fpm8.3", 0, 1, "php-fpm: master process", "/usr/sbin/php-fpm8.3")
JOURNALD = proc(285, "systemd-journal", 0, 1, "/usr/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald")
RSYSLOG_FDS = {672: {"7": "/var/log/syslog", "8": "/var/log/kern.log", "9": "/var/log/auth.log"}}


class TestHelpers(unittest.TestCase):
    def test_selector_kind(self):
        self.assertEqual(selector_kind("auth,authpriv.*"), "auth")
        self.assertEqual(selector_kind("*.*;auth,authpriv.none"), "all")
        self.assertEqual(selector_kind("*.=info;*.=notice;auth,authpriv.none;mail.none"), "all")
        self.assertIsNone(selector_kind("kern.*"))
        self.assertIsNone(selector_kind("mail.err"))

    def test_rotated_base(self):
        self.assertEqual(rotated_base("/var/log/auth.log.1"), "/var/log/auth.log")
        self.assertEqual(rotated_base("/var/log/syslog.7.gz"), "/var/log/syslog")
        self.assertEqual(rotated_base("/var/log/nginx/access.log-20261103.gz"), "/var/log/nginx/access.log")
        self.assertIsNone(rotated_base("/var/log/php8.3-fpm.log"))
        self.assertIsNone(rotated_base("/var/log/auth.log"))


class TestRsyslogParse(FakeRootTest):
    def test_real_ubuntu_config(self):
        root = self.make_root(logs())
        t = {x.path: x.kind for x in rsyslog_targets(Context(root, now=NOW))}
        self.assertEqual(t, {"/var/log/ufw.log": None, "/var/log/cloud-init.log": None, "/var/log/auth.log": "auth",
                             "/var/log/syslog": "all", "/var/log/kern.log": None, "/var/log/mail.log": None,
                             "/var/log/mail.err": None})

    def test_other_syntaxes(self):
        root = self.make_root({
            "/etc/rsyslog.conf": 'include(file="/etc/rsyslog.d/" mode="optional")\n$IncludeConfig /etc/extra/\n',
            "/etc/rsyslog.d/a.conf": 'if $programname == "sshd" then /var/log/sshd.log\n'
                                     'local0.* action(type="omfile"\n  file="/var/log/app.log")\n',
            "/etc/extra/b": "authpriv.*  /var/log/secure;RSYSLOG_FileFormat\n*.* @@10.0.0.1:514\n",
        })
        t = {x.path: x.kind for x in rsyslog_targets(Context(root, now=NOW))}
        self.assertEqual(t, {"/var/log/sshd.log": None, "/var/log/app.log": None, "/var/log/secure": "auth"})

    def test_no_rsyslog(self):
        self.assertIsNone(rsyslog_targets(Context(self.make_root({"/etc/hostname": "x\n"}), now=NOW)))


class TestLog01(ProcRootTest):
    check_class = Log01

    def run_check(self, files, procs=(RSYSLOGD,), fds=None, env=None):
        root = self.build(list(procs), files)
        for pid, table in (RSYSLOG_FDS if fds is None else fds).items():
            os.makedirs(os.path.join(root, "proc", str(pid), "fd"), exist_ok=True)
            for fd, target in table.items():
                os.symlink(target, os.path.join(root, "proc", str(pid), "fd", fd))
        ctx = LinkContext(root, NOW)
        ctx.env = env or {}
        check = Log01()
        check.RECHECK_SECONDS = 0
        return check, check.run(ctx)

    def test_linsecurity_clean(self):
        check, f = self.run_check(logs())
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "rsyslog 대상 7개, 웹 로그 0개, 그중 있는 파일 3개 (나머지 4개는 아직 만들어지지 않음), "
                                      "로그를 연 프로세스 1개")

    def test_ubuntu2404_web_server_clean(self):
        fds = dict(RSYSLOG_FDS)
        fds.update({767: {"2": "/var/log/nginx/error.log", "4": "/var/log/nginx/access.log"},
                    634: {"2": "/var/log/php8.3-fpm.log"},
                    285: {"23": "/var/log/journal/0ad5/system.journal",
                          "40": "/var/log/journal/0ad5/system@0001.journal (deleted)"}})  # journal은 LOG-04·05
        check, f = self.run_check(logs(**{"/etc/nginx/nginx.conf": NGINX_CONF,
                                          "/var/log/nginx/access.log": '10.0.0.1 - - "GET / HTTP/1.1" 200\n',
                                          "/var/log/nginx/error.log": "",  # 오류 로그는 비어도 정상
                                          "/var/log/php8.3-fpm.log": ""}),
                                  procs=(RSYSLOGD, NGINX, PHPFPM, JOURNALD), fds=fds)
        self.assertEqual(f, [])
        self.assertIn("웹 로그 2개, 그중 있는 파일 5개 (나머지 4개는 아직 만들어지지 않음)", check.scope)
        self.assertIn("로그를 연 프로세스 4개", check.scope)

    def test_lines_removed_with_sed(self):
        fds = {672: {"7": "/var/log/syslog", "9": "/var/log/auth.log (deleted)"}}
        _, f = self.run_check(logs(), fds=fds)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("/var/log/auth.log: 기록 중인 프로세스 1개가 지워진 원래 파일을 붙잡고 있다", f[0].reason)
        self.assertIn("다른 파일이 있다", f[0].reason)
        self.assertIn("fd 9 → /var/log/auth.log (deleted) | PID 672", f[0].evidence[0].detail)
        self.assertIn("cp /proc/672/fd/9", f[0].next_steps)

    def test_log_removed(self):
        files = logs(**{"/var/log/auth.log.1": LINE})
        del files["/var/log/auth.log"]
        _, f = self.run_check(files, fds={672: {"9": "/var/log/auth.log (deleted)"}})
        self.assertEqual(len(f), 1)  # 현재 파일 없음 + 순환 파일 있음은 같은 사건이라 따로 내지 않는다
        self.assertIn("지금 경로에 파일이 없다 (지워짐)", f[0].reason)

    def test_php_fpm_log_replaced_is_also_found(self):
        fds = dict(RSYSLOG_FDS)
        fds[634] = {"2": "/var/log/php8.3-fpm.log (deleted)"}
        _, f = self.run_check(logs(), procs=(RSYSLOGD, PHPFPM), fds=fds)
        self.assertEqual([x.reason.split(":")[0] for x in f], ["/var/log/php8.3-fpm.log"])

    def test_rotated_names_are_not_findings(self):
        fds = dict(RSYSLOG_FDS)
        fds[767] = {"4": "/var/log/nginx/access.log.1 (deleted)", "5": "/var/log/nginx/access.log-20261102.gz (deleted)"}
        check, f = self.run_check(logs(**{"/etc/nginx/nginx.conf": NGINX_CONF, "/var/log/nginx/access.log": "x\n"}),
                                  procs=(RSYSLOGD, NGINX), fds=fds)
        self.assertEqual(f, [])
        self.assertIn("순환된 이름으로 지워진 채 열린 파일 2개", check.scope)

    def test_truncated_while_open_leaves_nul(self):
        files = logs(**{"/var/log/syslog": b"\0" * 500 + b"Nov  3 03:10:01 linsecurity CRON[900]: (root) CMD\n"})
        _, f = self.run_check(files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("앞부분 500바이트가 NUL", f[0].reason)
        self.assertIn("이어지는 첫 줄: Nov  3 03:10:01 linsecurity CRON", f[0].evidence[0].detail)

    def test_empty_auth_log_with_sudo(self):
        _, f = self.run_check(logs(**{"/var/log/auth.log": ""}), env={"SUDO_USER": "bob"})
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("sudo(bob)", f[0].reason)

    def test_empty_logs_without_sudo(self):
        files = logs(**{"/var/log/auth.log": "", "/var/log/kern.log": "", "/var/log/mail.err": "",
                        "/etc/nginx/nginx.conf": NGINX_CONF, "/var/log/nginx/access.log": "",
                        "/var/log/nginx/error.log": ""})
        _, f = self.run_check(files)
        got = {x.reason.split(":")[0]: x.severity for x in f}
        # 커널·메일·오류 로그는 조용한 서버에서 비어도 정상
        self.assertEqual(got, {"/var/log/auth.log": "warning", "/var/log/nginx/access.log": "warning"})

    def test_broken_rotation_chain(self):
        files = logs(**{"/var/log/auth.log.2.gz": "x", "/var/log/auth.log.3.gz": "x",
                        "/var/log/syslog.1": LINE, "/var/log/syslog.2.gz": "x"})
        _, f = self.run_check(files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("/var/log/auth.log: 순환 파일 사이가 비어 있다 — 1 번이 없다", f[0].reason)

    def test_current_missing_but_rotated_exist(self):
        files = logs(**{"/var/log/auth.log.1": LINE})
        del files["/var/log/auth.log"]
        _, f = self.run_check(files, fds={672: {"7": "/var/log/syslog"}})
        self.assertEqual(len(f), 1)
        self.assertIn("현재 로그 파일은 없는데 순환 파일 1개가 있다", f[0].reason)

    def test_without_rsyslog(self):
        check, f = self.run_check({"/etc/hostname": "x\n"}, procs=(), fds={})
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "rsyslog 없음 (journald만), 웹 로그 0개, 로그를 연 프로세스 0개")

    def test_fake_root_ignores_real_sudo_environment(self):
        # 테스트를 sudo로 돌려도 가짜 루트 점검에는 도구 자신의 SUDO_USER를 쓰지 않는다
        root = self.build([RSYSLOGD], logs(**{"/var/log/auth.log": ""}))
        check = Log01()
        check.RECHECK_SECONDS = 0
        f = check.run(LinkContext(root, NOW))
        self.assertEqual([x.severity for x in f], ["warning"])


if __name__ == "__main__":
    unittest.main()
