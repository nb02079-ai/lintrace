"""PRC-01 실행 파일이 삭제된 채 도는 프로세스.

공격자는 악성 프로그램을 실행한 뒤 파일을 지워 흔적을 없앤다. 프로세스는 계속 돌고
/proc/<PID>/exe가 '<원래 경로> (deleted)'를 가리킨다. 지워진 파일도 /proc/<PID>/exe로
읽을 수 있으므로 SHA-256을 계산해 근거에 남긴다 (읽기만 하고 복사하지 않는다).

판정
- 심각: 원래 위치가 임시 폴더·숨김 경로
- 심각: 지워진 경로에 지금 아무 파일도 없음
- 참고: 같은 경로에 지금 파일이 있음 — 패키지 업데이트 후 재시작하지 않은 서비스에서 흔함.
        바꿔치기와 구분할 수 있게 실행 중인 파일과 디스크 파일의 해시를 함께 보인다.
- 제외: memfd 실행(파일 없는 실행, PRC-02가 맡음), 커널 스레드(실행 파일 없음)

같은 실행 파일로 도는 프로세스(워커 등)는 한 건으로 묶는다.
프로세스 정보는 collectors.processes가 한 번만 모은 표를 쓴다.
"""
from ..collectors.processes import evidence_for, processes
from .base import Check, Context, Evidence

TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")


def odd_location(path):
    if path.startswith(TEMP_DIRS):
        return "임시 폴더"
    if any(p.startswith(".") and p not in (".", "..") for p in path.split("/") if p):
        return "숨김 경로"
    return None


class Prc01(Check):
    id = "PRC-01"
    title = "실행 파일이 삭제된 채 도는 프로세스"
    severity = "critical"
    attack = "T1070.004"

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        groups = {}  # 지워진 경로 → [Proc]
        for p in table.procs:
            if not p.deleted or p.memfd or not p.exe_path.startswith("/"):
                continue  # 파일 없는 실행(memfd)은 PRC-02가 본다
            groups.setdefault(p.exe_path, []).append(p)
        self.scope = table.scope(ctx)
        return [self.report(ctx, path, groups[path]) for path in sorted(groups)]

    def report(self, ctx, path, procs):
        now_file = ctx.stat(path, follow=True)
        where = odd_location(path)
        running_hash = ctx.sha256("/proc/{}/exe".format(procs[0].pid))

        if where:
            severity = "critical"
            reason = "실행 파일이 지워진 채 도는 프로세스 {}개: 원래 위치 {}가 {}에 있다".format(len(procs), path, where)
        elif now_file is None:
            severity = "critical"
            reason = "실행 파일이 지워진 채 도는 프로세스 {}개: {}에 지금 아무 파일도 없다".format(len(procs), path)
        else:
            severity = "info"
            reason = ("실행 파일이 바뀐 뒤 재시작하지 않은 프로세스 {}개: {} (패키지 업데이트 후 흔함 — "
                      "아래 두 해시가 같은 패키지 버전인지 확인)".format(len(procs), path))

        evidence = evidence_for(ctx, procs)
        evidence.append(Evidence("/proc/{}/exe".format(procs[0].pid),
                                 "실행 중인 파일 SHA-256: {}".format(running_hash or "계산 불가")))
        if now_file is not None:
            evidence.append(Evidence(path, "지금 디스크에 있는 파일 SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))

        if severity == "critical":
            steps = ("SHA-256으로 악성코드 데이터베이스를 조회하고, 프로세스를 끝내기 전에 /proc/<PID>/exe를 "
                     "복사해 증거로 보존한다. 네트워크 연결(ss -p)과 부모 프로세스를 확인한다.")
        else:
            steps = ("두 해시가 다르면 'apt list --upgradable' 기록이나 dpkg 로그로 업데이트 여부를 확인하고, "
                     "정상 업데이트면 서비스를 재시작한다. 업데이트 기록이 없으면 바꿔치기를 의심한다.")
        return self.finding(reason=reason, next_steps=steps, evidence=evidence, severity=severity)
