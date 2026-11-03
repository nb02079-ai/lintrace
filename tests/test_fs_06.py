import os
import unittest

from lintrace.checks.base import Context, Unavailable
from lintrace.checks.fs_06 import Fs06, is_empty_php, snippet

from helpers import FakeRootTest

NOW = 1793600000.0
B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk" * 5


class TestHelpers(unittest.TestCase):
    def test_is_empty_php(self):
        self.assertTrue(is_empty_php("<?php\n// Silence is golden.\n"))
        self.assertTrue(is_empty_php("<?php /* nothing */ ?>"))
        self.assertFalse(is_empty_php("<?php echo 1; ?>"))

    def test_snippet_shortens_long_encoded_strings(self):
        text = "<?php eval(base64_decode('" + B64 + "')); ?>"
        s = snippet(text, 6, len(text))
        self.assertIn("…", s)
        self.assertLessEqual(len(s), 141)


class TestFs06(FakeRootTest):
    def scan(self, files, extra=None):
        root = self.make_root(dict(files, **(extra or {})))
        check = Fs06()
        return check, check.run(Context(root, now=NOW))

    def reasons(self, findings):
        return {f.evidence[0].source: (f.severity, f.reason.split(": ", 1)[1]) for f in findings}

    def test_no_web_server(self):
        check, f = self.scan({"/etc/hostname": "linsecurity\n"})  # lin.security: 웹 서버 없음
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "웹 루트 0개, 스크립트·이미지 파일 0개")

    def test_planted_webshells(self):
        """lin.security 양성 확인에 심을 파일과 같은 구성"""
        w = "/var/www/html/"
        check, f = self.scan({
            w + "shell.php": "<?php @eval($_POST['x']); ?>\n",
            w + "logo.jpg": "GIF89a<?php system($_GET['c']); ?>\n",
            w + "obf.php": "<?php eval(gzinflate(base64_decode('" + B64 + "'))); ?>\n",
            w + "uploads/a.php": "<?php echo 1; ?>\n",
            w + "index.php": '<?php echo "hello"; ?>\n',
        })
        r = self.reasons(f)
        self.assertEqual(r[w + "shell.php"], ("critical", "요청 값이 실행 함수로 바로 들어간다"))
        self.assertEqual(r[w + "logo.jpg"], ("critical", "이미지 확장자 파일 안에 PHP 코드가 있다 (업로드 검사 우회)"))
        self.assertEqual(r[w + "obf.php"], ("critical", "인코딩을 풀어 바로 실행한다"))
        self.assertEqual(r[w + "uploads/a.php"], ("warning", "업로드 폴더 안에 스크립트 파일이 있다"))
        self.assertNotIn(w + "index.php", r)
        self.assertEqual(check.scope, "웹 루트 1개 (/var/www), 스크립트·이미지 파일 5개")
        shell = [x for x in f if x.evidence[0].source.endswith("shell.php")][0]
        self.assertEqual(shell.evidence[0].detail, "1행: <?php @eval($_POST['x']); ?>")
        self.assertTrue(shell.evidence[-1].detail.startswith("속성 변경(ctime): "))

    def test_other_request_to_exec_forms(self):
        w = "/var/www/"
        _, f = self.scan({
            w + "a.php": "<?php\n\n$_GET['f']($_GET['c']);\n",
            w + "b.php": "<?php echo `{$_REQUEST['cmd']}`; ?>",
            w + "c.php": "<?php passthru( base64_decode($_COOKIE['z']) ); ?>",
            w + "d.php": "<?php preg_replace('/.*/e', $_POST['code'], ''); ?>",
            w + "e.php": "<?php $f = fopen('php://input','r'); assert(file_get_contents('php://input')); ?>",
        })
        r = self.reasons(f)
        self.assertEqual({k: v[0] for k, v in r.items()}, {w + n + ".php": "critical" for n in "abcde"})
        a = [x for x in f if x.evidence[0].source.endswith("a.php")][0]
        self.assertTrue(a.evidence[0].detail.startswith("3행: "))  # 줄 번호

    def test_benign_code_is_not_flagged(self):
        w = "/var/www/app/"
        _, f = self.scan({
            w + "db.php": "<?php\n$pdo->exec($sql);\n$this->system($_POST['name']);\nFoo::exec($_GET['q']);\n"
                          "$out = shell_exec('uptime');\n$m = \"do not eval user input like $_GET\";\n",
            w + "icon.php": "<?php $i = 'data:image/svg+xml;base64," + B64 + "'; ?>",
            w + "wp-content/uploads/index.php": "<?php\n// Silence is golden.\n",
            w + "images/logo.png": "\x89PNG\r\n\x1a\n binary data",
            w + "style.css": "body { color: red } /* $_GET eval( */",  # 대상 확장자가 아님
        })
        self.assertEqual(f, [])

    def test_long_decode_without_exec_is_warning(self):
        _, f = self.scan({"/var/www/x.php": "<?php $d = base64_decode('" + B64 + "'); file_put_contents('/tmp/a', $d);"})
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("난독화", f[0].reason)

    def test_roots_from_nginx_and_apache(self):
        check, f = self.scan({
            "/etc/nginx/sites-enabled/default": "server {\n  root /srv/site;  # 메인\n  location /s { alias /opt/static/; }\n"
                                                "  # root /commented/out;\n}\n",
            "/etc/apache2/sites-enabled/000-default.conf": 'DocumentRoot "/srv/legacy"\nAlias /x /srv/site/sub\n',
            "/srv/site/sub/a.php": "<?php system($_GET['c']);",
            "/srv/legacy/b.php": "<?php eval($_POST[1]);",
            "/opt/static/c.jpg": "<?php echo 1;",
        })
        self.assertEqual(check.scope.split(",")[0], "웹 루트 3개 (/opt/static")
        self.assertIn("/srv/legacy, /srv/site)", check.scope)  # /srv/site/sub은 /srv/site 안쪽이라 합침
        self.assertEqual(len(f), 3)

    def test_large_files_are_skipped(self):
        big = "<?php eval($_POST[1]); ?>" + "a" * (2 * 1024 * 1024)
        check, f = self.scan({"/var/www/big.php": big})
        self.assertEqual(f, [])
        self.assertIn("스크립트·이미지 파일 0개", check.scope)

    def test_unreadable_web_root_as_non_root(self):
        if os.geteuid() == 0:
            self.skipTest("root는 권한과 관계없이 읽을 수 있어 일반 계정에서만 확인 가능")
        root = self.make_root({"/var/www/secret/a.php": "<?php eval($_POST[1]);"})
        os.chmod(os.path.join(root, "var/www/secret"), 0o000)
        self.addCleanup(os.chmod, os.path.join(root, "var/www/secret"), 0o755)
        with self.assertRaises(Unavailable):
            Fs06().run(Context(root, now=NOW))


if __name__ == "__main__":
    unittest.main()
