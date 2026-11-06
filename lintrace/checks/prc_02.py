"""PRC-02 memfd에서 실행 중인 프로세스.

memfd_create로 메모리에만 만든 파일을 실행하면 디스크에 실행 파일이 남지 않는다 (파일 없는 악성코드).
/proc/<pid>/exe가 '/memfd:이름 (deleted)'로 보인다.

판정: 심각. 예외 — 컨테이너 런타임 runc가 자기 자신을 memfd로 다시 실행하는 것('memfd:runc_cloned…')은
2019년 runc 취약점(CVE-2019-5736) 대응으로 들어간 정상 동작이라 참고로 낮춘다.
실행 중인 내용은 /proc/<pid>/exe로 아직 읽을 수 있으므로 --out으로 보존한다.
"""
from ..collectors.processes import describe, processes
from .base import Check, Context, Evidence

RUNC = ("runc_cloned",)


def memfd_name(p):
    name = p.exe[len("/memfd:"):]
    return name[:-len(" (deleted)")] if name.endswith(" (deleted)") else name


class Prc02(Check):
    id = "PRC-02"
    title = "memfd에서 실행 중인 프로세스"
    severity = "critical"
    attack = "T1620"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        findings = []
        for p in table.procs:
            if not p.memfd:
                continue
            name = memfd_name(p)
            runc = name.startswith(RUNC)
            exe = "/proc/{}/exe".format(p.pid)
            label = "'{}'".format(p.name)
            extra = []
            if p.name.isdigit():
                # /proc/self/fd/N을 실행하면 이름(comm)이 파일 설명자 번호가 된다 — 명령줄을 함께 보여준다
                label += "(명령줄 {})".format(p.cmdline)
                extra.append(Evidence("/proc/{}/comm".format(p.pid), "이름 '{}' — /proc/self/fd/{}처럼 파일 설명자 경로로 "
                                      "실행한 흔적 (fexecve)".format(p.name, p.name)))
            findings.append(self.finding(
                reason="PID {} {}가 디스크에 없는 실행 파일(memfd:{})로 돌고 있다{}".format(
                    p.pid, label, name, " — runc 자기 재실행(컨테이너 런타임의 정상 동작)" if runc else
                    " — 파일 없는 악성코드의 전형적인 방식"),
                next_steps="프로세스를 끝내기 전에 '--out'으로 실행 중인 내용(/proc/PID/exe)을 보존하고, "
                           "부모 프로세스와 네트워크 연결(NET-02)을 확인한다.",
                evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now)),
                          Evidence(exe, "실행 파일 링크: {}".format(p.exe)),
                          Evidence(exe, "SHA-256: {}".format(ctx.sha256(exe) or "계산 불가"))] + extra,
                severity="info" if runc else None,
            ))
        self.scope = table.scope(ctx)
        return findings
