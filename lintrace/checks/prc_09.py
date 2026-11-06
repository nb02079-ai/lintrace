"""PRC-09 커널 스레드가 부모인 사용자 셸.

커널 취약점 공격(예: 네트워크 스택 원격 코드 실행)이 성공하면 커널이 call_usermodehelper로 셸을 띄우는데,
이때 셸의 부모가 kthreadd(PID 2)가 된다. 정상적으로 PID 2의 자식이 되는 사용자 프로그램은 modprobe,
apport(코어 덤프), request-key 같은 커널 도우미뿐이다.

판정 (심각): 부모가 PID 2인데 셸·인터프리터이거나, 실행 파일이 임시 폴더·숨김 경로·패키지 밖인 프로세스
"""
from ..collectors.packages import packages
from ..collectors.processes import describe, processes
from .base import Check, Context, Evidence
from .prc_01 import odd_location
from .prc_03 import interpreter_name


class Prc09(Check):
    id = "PRC-09"
    title = "커널 스레드가 부모인 사용자 셸"
    severity = "critical"
    attack = "T1068"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        db = packages(ctx)
        findings, children = [], 0
        for p in table.procs:
            if p.ppid != "2":
                continue
            children += 1
            why = []
            if interpreter_name(p):
                why.append("셸·인터프리터")
            where = odd_location(p.exe_path) if p.exe_path else None
            if where:
                why.append("실행 파일이 " + where)
            if db.available and p.exe_path and not p.memfd and db.owner(p.exe_path) is None:
                why.append("실행 파일이 패키지에 속하지 않음")
            if p.memfd:
                why.append("memfd 실행")
            if not why:
                continue
            findings.append(self.finding(
                reason="PID {} '{}'의 부모가 커널 스레드 kthreadd(PID 2)다 ({}) — 커널 공격이 띄운 셸일 수 있다".format(
                    p.pid, p.name, ", ".join(why)),
                next_steps="네트워크를 끊기 전에 이 프로세스의 입출력·연결(PRC-08, NET-02)과 실행 파일을 보존하고(--out), "
                           "같은 시각 커널 로그(dmesg, LOG-07)에 oops·KASAN 기록이 있는지 확인한다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now))],
            ))
        self.scope = "{}, PID 2의 사용자 프로세스 {}개".format(table.scope(ctx), children)
        return findings
