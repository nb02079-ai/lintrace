import os
import unittest

from lintrace.checks.base import Unavailable
from lintrace.checks.prc_01 import Prc01
from lintrace.checks.prc_03 import Prc03, interpreter_name, script_argument
from lintrace.collectors.processes import Proc, processes

from test_prc_01 import NOW, LinkContext, ProcRootTest, proc

INIT = proc(1, "systemd", 0, 0, "/sbin/init", "/usr/lib/systemd/systemd")


def p_with(exe, argv, cwd=None):
    p = Proc("9")
    p.exe, p.argv, p.cwd = exe, argv, cwd
    return p


class TestHelpers(unittest.TestCase):
    def test_interpreter_name(self):
        self.assertEqual(interpreter_name(p_with("/usr/bin/python3.6", ["python3", "x.py"])), "python")
        self.assertEqual(interpreter_name(p_with("/bin/bash", ["bash"])), "bash")
        self.assertEqual(interpreter_name(p_with("/usr/bin/perl", ["perl"])), "perl")
        self.assertIsNone(interpreter_name(p_with("/usr/sbin/nginx", ["nginx: worker"])))

    def test_script_argument(self):
        self.assertEqual(script_argument(p_with("/usr/bin/python3", ["python3", "-u", "/tmp/a.py", "x"])), "/tmp/a.py")
        self.assertEqual(script_argument(p_with("/bin/bash", ["bash", "./s.sh"], cwd="/dev/shm")), "/dev/shm/s.sh")
        self.assertIsNone(script_argument(p_with("/bin/bash", ["bash", "-c", "/tmp/x; echo"])))  # 인라인 코드
        self.assertIsNone(script_argument(p_with("/usr/bin/python3", ["python3", "-m", "http.server"])))
        self.assertIsNone(script_argument(p_with("/bin/bash", ["bash"])))  # 대화형 셸
        self.assertIsNone(script_argument(p_with("/bin/bash", ["bash", "s.sh"])))  # cwd 모름


class TestPrc03(ProcRootTest):
    check_class = Prc03

    def test_normal_processes(self):
        check, f = self.scan([INIT,
                              proc(50, "nginx", 33, 1, "nginx: worker process", "/usr/sbin/nginx"),
                              proc(51, "python3", 0, 1, "/usr/bin/python3 /usr/lib/app/run.py", "/usr/bin/python3.6"),
                              proc(52, "python3", 1000, 1, "python3 -m http.server", "/usr/bin/python3.6", cwd="/tmp"),
                              proc(53, "bash", 1000, 1, "-bash", "/bin/bash", cwd="/tmp"),
                              proc(54, "tool", 0, 1, "/tmpfiles/tool", "/tmpfiles/tool"),     # /tmp로 시작하지만 다른 폴더
                              proc(55, "x", 0, 1, "x", "/memfd:payload (deleted)")])          # PRC-02 몫
        self.assertEqual(f, [])
        self.assertEqual(check.scope, "프로세스 7개")

    def test_binary_in_temp_is_critical(self):
        _, f = self.scan([INIT,
                          proc(100, "kworker", 0, 1, "[kworker/0:2]", "/dev/shm/.x/kworker"),
                          proc(101, "kworker", 0, 100, "[kworker/0:2]", "/dev/shm/.x/kworker")])
        self.assertEqual(len(f), 1)  # 같은 실행 파일은 한 건으로
        self.assertEqual(f[0].severity, "critical")
        self.assertEqual(f[0].reason, "임시 폴더의 실행 파일로 도는 프로세스 2개: /dev/shm/.x/kworker")
        details = [e.detail for e in f[0].evidence]
        self.assertTrue(details[0].startswith("PID 100, 계정 root(0), 시작 1시간 전"))
        self.assertTrue(details[2].startswith("실행 파일 SHA-256: "))
        self.assertNotIn("PRC-01", " ".join(details))  # 지워지지 않았으므로 겹침 표시 없음

    def test_deleted_binary_is_cross_referenced_with_prc01(self):
        procs = [INIT, proc(19468, "lt-x", 0, 1, "/tmp/.lt-x 600", "/tmp/.lt-x (deleted)")]
        _, f3 = self.scan(procs)
        self.assertEqual(f3[0].severity, "critical")
        self.assertIn("PRC-01에서도 탐지 — 실행 파일이 지워진 상태", [e.detail for e in f3[0].evidence])
        # 같은 프로세스를 PRC-01도 잡는다 (서로 다른 사실이라 둘 다 낸다)
        self.check_class = Prc01
        _, f1 = self.scan(procs)
        self.assertIn("원래 위치 /tmp/.lt-x가 임시 폴더", f1[0].reason)

    def test_script_in_temp_is_warning(self):
        _, f = self.scan([INIT,
                          proc(200, "python3", 1000, 1, "python3 /tmp/.c/beacon.py --host 10.0.0.5", "/usr/bin/python3.6"),
                          proc(201, "bash", 0, 1, "bash ./run.sh", "/bin/bash", cwd="/var/tmp")],
                         extra={"/tmp/.c/beacon.py": "import socket\n"})
        self.assertEqual([x.severity for x in f], ["warning", "warning"])
        by_path = {x.reason.split(": ")[-1]: x for x in f}
        beacon = by_path["/tmp/.c/beacon.py"]
        self.assertIn("인터프리터가 임시 폴더의 스크립트를 실행 중인 프로세스 1개", beacon.reason)
        digest = beacon.evidence[-1].detail
        self.assertTrue(digest.startswith("스크립트 SHA-256: ") and "계산 불가" not in digest)
        run = by_path["/var/tmp/run.sh"]  # cwd 기준으로 푼 상대 경로
        self.assertIn("계산 불가 (파일이 없거나 읽을 수 없음)", run.evidence[-1].detail)

    def test_denied_processes(self):
        procs = [proc(1, "process_api", 0, 0, "process_api", "/usr/bin/process_api"),
                 proc(100, "m", 0, 1, "m", "/tmp/m")]
        if os.geteuid() != 0:
            with self.assertRaises(Unavailable):
                self.scan(procs, deny={"1"})
            return
        check, f = self.scan(procs, deny={"1"})
        self.assertEqual(len(f), 1)
        self.assertEqual(check.scope, "프로세스 1개(root로도 접근 거부된 1개 제외: PID 1 process_api)")


class TestSharedCollector(ProcRootTest):
    def test_proc_is_read_once_for_all_checks(self):
        root = self.build([INIT, proc(100, "m", 0, 1, "/tmp/m", "/tmp/m (deleted)")])
        ctx = LinkContext(root, NOW)
        f1 = Prc01().run(ctx)
        reads_after_first = ctx.exe_reads
        f3 = Prc03().run(ctx)
        self.assertEqual(ctx.exe_reads, reads_after_first)  # 두 번째 항목은 다시 읽지 않는다
        self.assertIs(processes(ctx), processes(ctx))
        self.assertEqual(len(f1) + len(f3), 2)  # 같은 표에서 두 항목이 각자 판단


if __name__ == "__main__":
    unittest.main()
