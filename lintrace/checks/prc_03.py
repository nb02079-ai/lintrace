"""PRC-03 임시 디렉터리에서 실행 중인 프로세스.

공격자가 내려받은 도구는 대개 누구나 쓸 수 있는 /tmp, /var/tmp, /dev/shm에서 실행된다.
정상 서버에서는 드문 일이라 강한 신호다.

판정
- 심각: 실행 파일 자체가 임시 폴더에 있음 (/tmp/x, /dev/shm/.a/b)
- 위험: 인터프리터가 임시 폴더의 스크립트를 실행 중 (python3 /tmp/x.py, bash /dev/shm/s.sh)
        — 설치 프로그램 등이 임시 스크립트를 정상적으로 쓰는 경우가 있어 한 단계 낮춤
- 제외: memfd 실행 (PRC-02), 인라인 코드(-c, -e)와 모듈 실행(-m)

실행 파일이 지워지기까지 했으면 PRC-01도 같은 프로세스를 잡는다. 서로 다른 사실이라
둘 다 내고, 근거에 "PRC-01에서도 탐지"를 표시한다 (3단계 상관분석에서 한 사건으로 묶인다).
"""
import posixpath
import re

from ..collectors.processes import evidence_for, processes
from .base import Check, Context, Evidence

TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
INTERPRETER = re.compile(r"^(?:(?:ba|da|z|k|a)?sh|busybox|python|perl|php|ruby|node|lua|tclsh)$")
# 이 옵션이 나오면 뒤따르는 것은 파일이 아니라 코드 문자열이나 모듈 이름이다
INLINE = {"-c", "-e", "-E", "-m", "-r", "--eval", "--command"}


def in_temp(path):
    return bool(path) and path.startswith(TEMP_DIRS)


def interpreter_name(p):
    """프로세스가 인터프리터면 정규화된 이름 (python3.6 → python), 아니면 None."""
    for candidate in (p.exe_path, p.argv[0] if p.argv else ""):
        base = posixpath.basename(candidate or "")
        norm = re.sub(r"[\d.]+$", "", base)
        if INTERPRETER.match(norm):
            return norm
    return None


def script_argument(p):
    """인터프리터가 실행 중인 스크립트 파일. 인라인 코드·모듈 실행이면 None."""
    for arg in p.argv[1:]:
        if arg in INLINE:
            return None
        if arg.startswith("-"):
            continue
        if arg.startswith("/"):
            return posixpath.normpath(arg)
        if p.cwd and p.cwd.startswith("/"):
            # 상대 경로는 프로세스의 작업 폴더 기준 (예: cd /tmp && bash ./x.sh)
            return posixpath.normpath(posixpath.join(p.cwd.replace(" (deleted)", ""), arg))
        return None
    return None


class Prc03(Check):
    id = "PRC-03"
    title = "임시 디렉터리에서 실행 중인 프로세스"
    severity = "critical"
    attack = "T1059"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        binaries, scripts = {}, {}  # 경로 → [Proc]
        for p in table.procs:
            if p.memfd:
                continue  # 파일 없는 실행은 PRC-02가 본다
            if in_temp(p.exe_path):
                binaries.setdefault(p.exe_path, []).append(p)
                continue
            if interpreter_name(p):
                script = script_argument(p)
                if in_temp(script):
                    scripts.setdefault(script, []).append(p)

        findings = []
        for path in sorted(binaries):
            findings.append(self.report_binary(ctx, path, binaries[path]))
        for path in sorted(scripts):
            findings.append(self.report_script(ctx, path, scripts[path]))
        self.scope = table.scope(ctx)
        return findings

    def report_binary(self, ctx, path, procs):
        evidence = evidence_for(ctx, procs)
        evidence.append(Evidence("/proc/{}/exe".format(procs[0].pid), "실행 파일 SHA-256: {}".format(
            ctx.sha256("/proc/{}/exe".format(procs[0].pid)) or "계산 불가")))
        if any(p.deleted for p in procs):
            evidence.append(Evidence(path, "PRC-01에서도 탐지 — 실행 파일이 지워진 상태"))
        return self.finding(
            reason="임시 폴더의 실행 파일로 도는 프로세스 {}개: {}".format(len(procs), path),
            next_steps="SHA-256으로 악성코드 데이터베이스를 조회하고, 프로세스를 끝내기 전에 실행 파일을 증거로 "
                       "보존한다. 이 파일을 내려받은 경로(명령 기록, 웹 서버 로그)와 네트워크 연결(ss -p)을 확인한다.",
            evidence=evidence,
            severity="critical",
        )

    def report_script(self, ctx, path, procs):
        evidence = evidence_for(ctx, procs)
        digest = ctx.sha256(path)
        evidence.append(Evidence(path, "스크립트 SHA-256: {}".format(digest or "계산 불가 (파일이 없거나 읽을 수 없음)")))
        return self.finding(
            reason="인터프리터가 임시 폴더의 스크립트를 실행 중인 프로세스 {}개: {}".format(len(procs), path),
            next_steps="스크립트 내용을 확인하고(파일이 지워졌으면 프로세스를 끝내기 전에 /proc/<PID>/fd에서 찾아 "
                       "보존), 설치 프로그램 같은 정상 작업인지 부모 프로세스와 실행 계정으로 판단한다.",
            evidence=evidence,
            severity="warning",
        )
