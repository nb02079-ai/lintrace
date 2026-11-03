import os
import unittest

from lintrace.checks.base import Context, Unavailable
from lintrace.checks.prc_01 import Prc01, odd_location

from helpers import FakeRootTest

NOW = 1793600000.0
BTIME = int(NOW) - 7200  # 2시간 전 부팅


def stat_line(pid, name, start_ticks):
    # 마지막 ')' 뒤 20번째 필드가 starttime (부팅 후 클럭 틱)
    return "{} ({}) S ".format(pid, name) + " ".join(["1"] * 18) + " {}\n".format(start_ticks)


def proc(pid, name, uid, ppid, cmdline, exe, start_ticks=360000):
    """가짜 /proc/<pid>. exe는 링크 대상 문자열 그대로 (None이면 커널 스레드처럼 exe 없음)."""
    files = {
        "/proc/{}/status".format(pid): "Name:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\n".format(name, ppid, uid, uid, uid, uid),
        "/proc/{}/cmdline".format(pid): cmdline.replace(" ", "\0"),
        "/proc/{}/comm".format(pid): name + "\n",
        "/proc/{}/stat".format(pid): stat_line(pid, name, start_ticks),
    }
    return files, (pid, exe)


class TestHelpers(unittest.TestCase):
    def test_odd_location(self):
        self.assertEqual(odd_location("/tmp/.x/miner"), "임시 폴더")
        self.assertEqual(odd_location("/usr/lib/.cache/upd"), "숨김 경로")
        self.assertIsNone(odd_location("/usr/sbin/nginx"))


class LinkContext(Context):
    """권한 거부를 흉내 낼 PID를 지정할 수 있는 Context (root는 디렉터리 권한을 무시하므로)."""

    def __init__(self, root, now, deny=()):
        Context.__init__(self, root, now)
        self.deny = set(deny)

    def readlink(self, p, strict=False):
        pid = p.split("/")[2] if p.startswith("/proc/") else None
        if strict and pid in self.deny:
            raise Unavailable("{} 읽기 권한 없음".format(p))
        return Context.readlink(self, p, strict)


class TestPrc01(FakeRootTest):
    def build(self, procs, extra=None):
        files = {"/proc/stat": "cpu  1 2 3\nbtime {}\n".format(BTIME),
                 "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n"
                                "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"}
        links = []
        for f, link in procs:
            files.update(f)
            links.append(link)
        files.update(extra or {})
        root = self.make_root(files)
        for pid, exe in links:
            if exe is not None:
                os.symlink(exe, os.path.join(root, "proc", str(pid), "exe"))
        return root

    def scan(self, procs, extra=None, deny=()):
        root = self.build(procs, extra)
        check = Prc01()
        return check, check.run(LinkContext(root, NOW, deny))

    def test_normal_processes(self):
        check, f = self.scan([proc(1, "systemd", 0, 0, "/sbin/init", "/usr/lib/systemd/systemd"),
                              proc(2, "kthreadd", 0, 0, "", None)])  # 커널 스레드는 exe가 없다
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "프로세스 2개")

    def test_deleted_from_hidden_temp_dir(self):
        _, f = self.scan([proc(1, "systemd", 0, 0, "/sbin/init", "/usr/lib/systemd/systemd"),
                          proc(100, "miner", 1000, 1, "/tmp/.x/miner -o pool", "/tmp/.x/miner (deleted)")])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("원래 위치 /tmp/.x/miner가 임시 폴더에 있다", f[0].reason)
        detail = f[0].evidence[0].detail
        self.assertIn("PID 100, 계정 bob(1000)", detail)
        self.assertIn("시작 1시간 전", detail)               # 부팅 2시간 전 + 시작 3600초 뒤
        self.assertIn("부모 PID 1(systemd): /tmp/.x/miner -o pool", detail)
        self.assertTrue(f[0].evidence[-1].detail.startswith("실행 중인 파일 SHA-256: "))
        self.assertIn("복사해 증거로 보존", f[0].next_steps)

    def test_deleted_and_gone_is_critical(self):
        _, f = self.scan([proc(300, "agent", 0, 1, "/opt/app/agent", "/opt/app/agent (deleted)")])
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("/opt/app/agent에 지금 아무 파일도 없다", f[0].reason)

    def test_replaced_after_update_is_info_and_grouped(self):
        procs = [proc(p, "nginx", 33, 200, "nginx: worker process", "/usr/sbin/nginx (deleted)") for p in (201, 202)]
        procs.insert(0, proc(200, "nginx", 0, 1, "nginx: master process", "/usr/sbin/nginx (deleted)"))
        _, f = self.scan(procs, extra={"/usr/sbin/nginx": "\x7fELF new version"})
        self.assertEqual(len(f), 1)  # 같은 실행 파일의 프로세스는 한 건으로
        self.assertEqual(f[0].severity, "info")
        self.assertIn("재시작하지 않은 프로세스 3개: /usr/sbin/nginx", f[0].reason)
        details = [e.detail for e in f[0].evidence]
        self.assertEqual(sum(d.startswith("PID ") for d in details), 3)
        self.assertTrue(details[-1].startswith("지금 디스크에 있는 파일 SHA-256: "))
        self.assertNotIn("계산 불가", details[-1])
        self.assertIn("apt", f[0].next_steps)

    def test_memfd_is_left_to_prc02(self):
        _, f = self.scan([proc(400, "x", 0, 1, "x", "/memfd:payload (deleted)")])
        self.assertEqual(f, [])

    def test_many_processes_are_summarized(self):
        procs = [proc(p, "w", 0, 1, "w", "/opt/w (deleted)") for p in range(500, 515)]
        _, f = self.scan(procs)
        details = [e.detail for e in f[0].evidence]
        self.assertEqual(sum(d.startswith("PID ") for d in details), 10)
        self.assertIn("외 5개 프로세스", " ".join(details))

    def test_denied_processes(self):
        procs = [proc(1, "process_api", 0, 0, "process_api", "/usr/bin/process_api"),
                 proc(100, "miner", 0, 1, "m", "/tmp/m (deleted)")]
        if os.geteuid() != 0:
            # root가 아니면 부분 결과를 정상처럼 내지 않는다
            with self.assertRaises(Unavailable):
                self.scan(procs, deny={"1"})
            return
        # root인데 일부만 거부되면 나머지 결과는 내고, 거부된 프로세스를 밝힌다
        check, f = self.scan(procs, deny={"1"})
        self.assertEqual(len(f), 1)
        self.assertEqual(check.scope, "프로세스 1개(root로도 접근 거부된 1개 제외: PID 1 process_api)")


if __name__ == "__main__":
    unittest.main()
