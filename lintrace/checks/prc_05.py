"""PRC-05 ps 결과와 /proc 목록 불일치.

루트킷은 프로세스를 숨긴다. 사용자 공간 루트킷(libprocesshider 등)은 /proc 디렉터리 읽기(readdir)나 ps를
가로채고, 커널 루트킷은 /proc 목록에서 지운다. 그래도 kill(pid, 0)이나 /proc/<pid> 직접 접근에는 보이는
경우가 많다. 세 가지 보는 방법을 맞대어 한쪽에서만 안 보이는 PID를 찾는다.

1. kill(pid, 0)으로 PID 1~pid_max 전체를 훑어 살아 있는 PID (24.04 pid_max 4,194,304 → 약 2.5초)
2. /proc 디렉터리 목록
3. 'ps -e' 결과 (읽기만 하는 명령)

판정 (심각)
- kill에는 응답하는데 /proc 목록에 없는 프로세스 (스레드 ID도 kill에 응답하므로 /proc/<pid>/status의
  Tgid가 자기 자신인 것만, 그사이 새로 생긴 프로세스를 빼려고 목록을 한 번 더 읽어 확인)
- /proc 목록에 있는데 ps에 없는 프로세스 (ps를 돌리기 전부터 있었고 끝난 뒤에도 살아 있는 것만)
실제 시스템(--root /)에서만 한다.
"""
import os
import shutil
import subprocess

from .base import Check, Context, Evidence, Unavailable


class Prc05(Check):
    id = "PRC-05"
    title = "ps 결과와 /proc 목록 불일치"
    severity = "critical"
    attack = "T1014"

    def run(self, ctx: Context):
        if not self.live(ctx):
            self.scope = "실제 시스템에서만 점검 (--root 지정됨)"
            return []
        listed = self.listing(ctx)
        pid_max = self.pid_max(ctx)
        alive = self.alive(pid_max)
        relisted = self.listing(ctx)
        hidden = []
        for pid in sorted(alive - listed - relisted):
            if self.is_process(ctx, pid) and self.still_alive(pid) and str(pid) not in self.listing_names(ctx):
                hidden.append(pid)
        findings = [self.report_hidden(ctx, pid) for pid in hidden]

        ps = self.ps_pids()
        ps_note = "ps 없음 — 비교 생략"
        if ps is not None:
            after = self.listing(ctx)
            missing = sorted(pid for pid in (listed & after) - ps if pid != os.getpid() and self.still_alive(pid))
            for pid in missing:
                findings.append(self.report_ps(ctx, pid))
            ps_note = "ps {}개".format(len(ps))
        self.scope = "PID 1~{:,} (/proc {}개, {})".format(pid_max, len(listed), ps_note)
        return findings

    # --- 세 가지 보는 방법 (테스트에서 바꿔 끼운다) ---

    @staticmethod
    def live(ctx):
        return ctx.root == "/"

    @staticmethod
    def listing_names(ctx):
        return [n for n in ctx.list_dir("/proc") if n.isdigit()]

    def listing(self, ctx):
        return {int(n) for n in self.listing_names(ctx)}

    @staticmethod
    def pid_max(ctx):
        lines = ctx.read_lines("/proc/sys/kernel/pid_max", missing_ok=True)
        try:
            return int(lines[0])
        except (IndexError, ValueError):
            return 32768

    @staticmethod
    def alive(pid_max):
        out = set()
        for pid in range(1, pid_max + 1):
            try:
                os.kill(pid, 0)
                out.add(pid)
            except ProcessLookupError:
                pass
            except PermissionError:
                out.add(pid)  # 남의 프로세스 — 살아 있다
            except OSError:
                pass
        return out

    @staticmethod
    def still_alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True
        return True

    @staticmethod
    def is_process(ctx, pid):
        """스레드가 아니라 프로세스(Tgid == pid)인지. status를 못 읽으면 숨긴 것일 수 있어 프로세스로 본다."""
        try:
            lines = ctx.read_lines("/proc/{}/status".format(pid), missing_ok=True)
        except Unavailable:
            return True
        for line in lines:
            if line.startswith("Tgid:"):
                return line.split()[1] == str(pid)
        return True

    @staticmethod
    def ps_pids():
        ps = shutil.which("ps")
        if not ps:
            return None
        try:
            out = subprocess.run([ps, "-e", "-o", "pid="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 universal_newlines=True, timeout=60).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        return {int(x) for x in out.split() if x.isdigit()}

    # --- 근거 ---

    @staticmethod
    def info(ctx, pid):
        base = "/proc/{}".format(pid)
        ev = []
        exe = ctx.readlink(base + "/exe")
        ev.append(Evidence(base, "실행 파일: {}".format(exe or "읽지 못함")))
        raw = b""
        try:
            raw = ctx.read_head(base + "/cmdline", 4096)
        except Unavailable:
            pass
        ev.append(Evidence(base, "명령줄: {}".format(" ".join(a.decode("utf-8", "replace") for a in raw.split(b"\0") if a)
                                                     or "(비어 있음)")))
        return ev

    def report_hidden(self, ctx, pid):
        return self.finding(
            reason="PID {}는 살아 있는데(kill 응답) /proc 목록에 나오지 않는다 — 루트킷이 숨긴 프로세스".format(pid),
            next_steps="/proc/{0}/exe·maps·fd를 직접 열어 보존하고(--out), 숨긴 수단(ld.so.preload — PER-05, 커널 모듈 — "
                       "PER-06)을 찾는다. 이 시스템의 도구 결과는 신뢰하기 어려우므로 외부 매체로 부팅해 다시 본다.".format(pid),
            evidence=self.info(ctx, pid),
        )

    def report_ps(self, ctx, pid):
        return self.finding(
            reason="PID {}는 /proc에 있는데 ps 결과에 없다 — ps가 바꿔치기됐거나 라이브러리가 결과를 숨긴다".format(pid),
            next_steps="ps 실행 파일(FS-04 패키지 무결성)과 /etc/ld.so.preload(PER-05)를 확인하고, 숨겨진 프로세스를 보존한다.",
            evidence=self.info(ctx, pid),
        )
