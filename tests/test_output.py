"""JSON 결과와 증거 아카이브 (2-0)."""
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import shutil
import unittest
from contextlib import redirect_stderr, redirect_stdout

from lintrace import archive, code_sha256
from lintrace.__main__ import main
from lintrace.checks import ALL_CHECKS
from lintrace.checks.base import Context

from helpers import FakeRootTest

PASSWD = "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\nx:x:0:0::/:/bin/sh\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class TestCodeHash(unittest.TestCase):
    def test_same_as_shell_command(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base)
        files = {"lintrace/a_b.py": b"1", "lintrace/a.b.py": b"2", "tests/t.py": b"3", "rules/c.json": b"{}",
                 "lintrace/__pycache__/a.cpython-36.pyc": b"x", "lintrace/notes.txt": b"x", "docs/d.py": b"x"}
        for rel, data in files.items():
            os.makedirs(os.path.join(base, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(base, rel), "wb") as f:
                f.write(data)
        # find lintrace tests rules -type f \( -name '*.py' -o -name '*.json' \) | LC_ALL=C sort | xargs sha256sum | sha256sum
        listed = ["lintrace/a.b.py", "lintrace/a_b.py", "rules/c.json", "tests/t.py"]  # '.'(0x2e) < '_'(0x5f)
        expected = sha("".join("{}  {}\n".format(sha(files[p]), p) for p in listed).encode())
        self.assertEqual(code_sha256(base), expected)


class TestJson(FakeRootTest):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_every_check_with_status(self):
        root = self.make_root({"/etc/passwd": PASSWD, "/etc/sudoers": None,  # 디렉터리라 읽을 수 없음
                               "/etc/hostname": "web01\n",
                               "/etc/os-release": 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.4 LTS"\n'})
        code, out, _ = self.run_main(["--root", root, "--json", "-"])
        self.assertEqual(code, 0)
        d = json.loads(out)  # '-'면 텍스트 리포트 없이 JSON만
        self.assertEqual(d["schema"], 1)
        self.assertEqual(d["tool"]["name"], "lintrace")
        self.assertEqual(len(d["tool"]["code_sha256"]), 64)
        self.assertEqual(d["run"]["host"], "web01")
        self.assertEqual(d["run"]["os"], "Ubuntu 24.04.4 LTS")
        self.assertIsNone(d["run"]["kernel"])  # 가짜 루트에는 도구 자신의 커널을 넣지 않는다
        self.assertEqual(d["verdict"], "critical")
        self.assertTrue(d["incomplete"])
        self.assertEqual([c["id"] for c in d["checks"]], [c.id for c in ALL_CHECKS])
        status = {c["id"]: c["status"] for c in d["checks"]}
        self.assertEqual(status["ACC-01"], "detected")
        self.assertEqual(status["ACC-06"], "unavailable")
        self.assertEqual(status["ACC-07"], "clean")
        acc06 = [c for c in d["checks"] if c["id"] == "ACC-06"][0]
        self.assertIsNone(acc06["scope"])
        self.assertIn("디렉터리", acc06["error"])
        acc01 = [c for c in d["checks"] if c["id"] == "ACC-01"][0]
        self.assertEqual(acc01["scope"], "계정 3개")
        self.assertEqual(acc01["findings"][0]["evidence"][0]["source"], "/etc/passwd")
        # ACC-06·08·09 + 가짜 루트에 /proc/modules·dpkg 정보가 없는 PER-07·FS-04·FS-05
        self.assertEqual(d["counts"], {"checks": len(ALL_CHECKS), "findings": 1, "unavailable": 6,
                                       "critical": 1, "warning": 0, "info": 0})

    def test_json_file_matches_text_report(self):
        root = self.make_root({"/etc/passwd": PASSWD})
        path = os.path.join(self.make_root({}), "r.json")
        code, out, err = self.run_main(["--root", root, "--json", path])
        self.assertTrue(out.startswith("전체 판정: 심각"))
        self.assertIn("JSON 결과: " + path, err)
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        for c in d["checks"]:
            for f_ in c["findings"]:
                self.assertIn(f_["reason"], out)  # 텍스트와 같은 결과
            if c["scope"]:
                self.assertIn("{} — {}".format(c["id"], c["scope"]), out)


class TestArchive(FakeRootTest):
    def test_archive_layout(self):
        root = self.make_root({"/etc/passwd": PASSWD, "/etc/hostname": "web01\n"})
        out_dir = os.path.join(self.make_root({}), "evidence-out")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(main(["--root", root, "--out", out_dir]), 0)
        names = sorted(os.listdir(out_dir))
        self.assertEqual(len(names), 2)
        folder, tar_name = names[0], names[1]
        self.assertTrue(folder.startswith("lintrace-web01-"))
        self.assertEqual(tar_name, folder + ".tar.gz")
        d = os.path.join(out_dir, folder)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)

        copy = os.path.join(d, "evidence", "etc", "passwd")
        with open(copy, "rb") as f:
            self.assertEqual(f.read(), PASSWD.encode())  # 원본 그대로 (리포트와 달리 해시를 가리지 않음)
        self.assertEqual(stat.S_IMODE(os.stat(copy).st_mode), 0o400)

        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
        entry = m["files"][0]
        self.assertEqual(entry["source"], "/etc/passwd")
        self.assertTrue(entry["copied"])
        self.assertEqual(entry["sha256"], sha(PASSWD.encode()))
        self.assertEqual(entry["size"], len(PASSWD))

        with open(os.path.join(d, "SHA256SUMS"), encoding="utf-8") as f:
            sums = dict(reversed(line.rstrip("\n").split("  ", 1)) for line in f)
        self.assertEqual(sorted(sums), ["evidence/etc/passwd", "manifest.json", "report.html", "report.json", "report.txt"])
        for rel, h in sums.items():
            with open(os.path.join(d, rel), "rb") as f:
                self.assertEqual(sha(f.read()), h, rel)

        with open(os.path.join(d, "report.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["archive"], {"name": folder, "evidence_files": 1})
        with tarfile.open(os.path.join(out_dir, tar_name)) as t:
            self.assertIn(folder + "/evidence/etc/passwd", t.getnames())
        tar_hash = sha(open(os.path.join(out_dir, tar_name), "rb").read())
        self.assertIn("묶음 SHA-256: " + tar_hash, err.getvalue())
        self.assertIn("민감 정보", err.getvalue())

    def test_same_second_runs_do_not_overwrite(self):
        out_dir = self.make_root({})
        ctx = Context(self.make_root({}), now=1793600000.0)
        a1 = archive.Archive(out_dir, ctx, "h", ctx.now)
        a1.create()
        a2 = archive.Archive(out_dir, ctx, "h", ctx.now)
        a2.create()
        self.assertEqual(a2.name, a1.name + "-2")

    def test_deleted_file_held_open_is_recovered(self):
        """sed -i로 지운 로그처럼, 프로세스가 붙잡은 지워진 파일의 원래 내용을 /proc/PID/fd로 복사한다."""
        tmp = self.make_root({})
        path = os.path.join(tmp, "auth.log")
        with open(path, "w") as f:
            f.write("Nov  3 sudo: bob : COMMAND=/bin/bash\n")
        held = open(path)
        self.addCleanup(held.close)
        os.remove(path)
        a = archive.Archive(self.make_root({}), Context("/"), "h", 1793600000.0)
        a.create()
        e = a.add_evidence("/proc/self/fd/{}".format(held.fileno()))
        self.assertTrue(e["copied"], e)
        self.assertTrue(e["link_target"].endswith("auth.log (deleted)"))
        with open(os.path.join(a.dir, *e["path"].split("/")), encoding="utf-8") as f:
            self.assertIn("COMMAND=/bin/bash", f.read())

    def test_size_limit_records_hash_only(self):
        root = self.make_root({"/var/log/big.log": "x" * 2000})
        a = archive.Archive(self.make_root({}), Context(root), "h", 1793600000.0)
        a.create()
        old = archive.FILE_LIMIT
        archive.FILE_LIMIT = 1000
        self.addCleanup(setattr, archive, "FILE_LIMIT", old)
        e = a.add_evidence("/var/log/big.log")
        self.assertFalse(e["copied"])
        self.assertEqual(e["sha256"], sha(b"x" * 2000))
        self.assertIn("크기 제한 초과", e["note"])
        self.assertFalse(os.path.exists(os.path.join(a.dir, "evidence", "var")))

    def test_non_regular_sources_are_not_opened(self):
        root = self.make_root({"/var/log": None})
        os.mkfifo(os.path.join(root, "var", "log", "pipe"))
        a = archive.Archive(self.make_root({}), Context(root), "h", 1793600000.0)
        a.create()
        self.assertIn("일반 파일이 아님", a.add_evidence("/var/log/pipe")["note"])  # 멈추면 실패
        self.assertIn("일반 파일이 아님", a.add_evidence("/var/log")["note"])
        self.assertIn("읽을 수 없음", a.add_evidence("/var/log/none")["note"])


if __name__ == "__main__":
    unittest.main()
