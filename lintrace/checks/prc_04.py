"""PRC-04 커널 스레드 이름 위장 프로세스.

진짜 커널 스레드(kworker, ksoftirqd 등)는 실행 파일이 없고 명령줄이 비어 ps에 '[kworker/0:1]'처럼 대괄호로
보인다. 악성 프로세스는 argv[0]이나 이름(comm)을 이렇게 바꿔 ps 목록에 섞인다.

판정 (심각)
- 실행 파일이 있는 사용자 프로세스인데 명령줄이 대괄호로 싸여 있음 ('[kworker/0:1]')
- 실행 파일이 있는데 이름(comm)이 커널 스레드 이름 꼴이고 실행 파일 이름과 다름
  (watchdog 패키지의 /usr/sbin/watchdog처럼 실행 파일 이름과 같으면 정상)
"""
import posixpath
import re

from ..collectors.processes import describe, processes
from .base import Check, Context, Evidence

KTHREAD = re.compile(r"^(kworker|ksoftirqd|kthreadd|kswapd\d*|migration|rcu_\w+|kauditd|khugepaged|kcompactd\d*|"
                     r"jbd2|irq/|kblockd|kdevtmpfs|kthrotld|writeback|kintegrityd|watchdogd|cpuhp|netns|oom_reaper)")


class Prc04(Check):
    id = "PRC-04"
    title = "커널 스레드 이름 위장 프로세스"
    severity = "critical"
    attack = "T1036.004"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        findings = []
        for p in table.procs:
            argv0 = p.argv[0] if p.argv else ""
            exe_base = posixpath.basename(p.exe_path or "")
            reasons = []
            if argv0.startswith("[") and argv0.rstrip().endswith("]"):
                reasons.append("명령줄이 커널 스레드처럼 대괄호로 싸여 있다 ({})".format(argv0))
            if KTHREAD.match(p.name) and p.name != exe_base:
                reasons.append("이름(comm)이 커널 스레드 꼴이다 ({})".format(p.name))
            if not reasons:
                continue
            findings.append(self.finding(
                reason="PID {}: {} — 그런데 실제 실행 파일 {}가 있는 사용자 프로세스다".format(
                    p.pid, "; ".join(reasons), p.exe),
                next_steps="실행 파일을 보존하고(--out) 부모 프로세스·네트워크 연결·시작 방법(cron, systemd)을 확인한다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now)),
                          Evidence("/proc/{}/exe".format(p.pid), "실행 파일 링크: {}".format(p.exe))],
            ))
        self.scope = table.scope(ctx)
        return findings
