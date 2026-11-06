"""NET-01 예상 목록 밖의 리스닝 포트.

포트 번호로 정상 여부를 가리려면 그 서버의 평소 상태(기준선)가 필요하다 — 3단계에서 만든다.
그 전까지는 '누가 리스닝하는가'로 본다 (2026-11-06 결정).

판정 (위험)
- 리스닝하는 프로세스가 셸·인터프리터·nc·socat이거나, 실행 파일이 지워짐·memfd·임시 폴더·숨김 경로·패키지 밖
- 소켓에 inode가 있는데 어느 프로세스의 열린 파일에도 없음 — 숨긴 프로세스의 단서 (PRC-05와 교차)
  (inode가 0인 소켓은 커널이 직접 연 것 — 정상, 범위에 개수만)
  커널 NFS(nfsd·lockd)가 연 소켓도 inode는 있는데 주인 프로세스가 없다 (lin.security 정답, 2026-11-06).
  nfsd·lockd 모듈이 있을 때 uid 0 소켓을 nfsd 포트 목록·nlm 포트·rpcbind 등록과 맞대어 맞으면 정상
  (collectors/nfs.py). rpcbind 등록을 읽지 못했는데 lockd가 있으면 남은 uid 0 소켓은 참고로 낮춘다
  (lockd 포트는 부팅마다 바뀌어 다른 방법으로는 가릴 수 없다).
전체 리스닝 목록은 점검 범위에 보여준다.
"""
from ..collectors.processes import describe, processes
from ..collectors.nfs import kernel_nfs
from ..collectors.sockets import read_inet, sockets
from .base import Check, Context, Evidence
from .procnet import exe_name, suspicious

MAX_SCOPE = 15


def port_key(s):
    return "{}/{}".format("tcp" if s.proto.startswith("tcp") else "udp", s.local[1])


class Net01(Check):
    id = "NET-01"
    title = "예상 목록 밖의 리스닝 포트"
    severity = "warning"
    attack = "T1571"
    RPCINFO = None  # rpcbind 등록 목록을 돌려주는 함수 (테스트에서 바꿔 끼운다)

    def run(self, ctx: Context):
        table = processes(ctx)
        table.require_access()
        listeners = [s for s in sockets(ctx).socks if s.listening]
        unknown_owner_possible = bool(table.denied or table.fd_denied)
        findings, summary, kernel, nfs_count = [], {}, 0, 0
        reported = set()
        for s in listeners:
            key = port_key(s)
            if s.kernel:
                kernel += 1
                summary.setdefault(key, set()).add("커널")
                continue
            if not s.owners:
                if unknown_owner_possible or not self.still_listening(ctx, s):
                    summary.setdefault(key, set()).add("?")
                    continue  # 열린 파일을 못 읽은 프로세스가 주인이거나, 그사이 닫힌 소켓
                nfs = kernel_nfs(ctx, self.RPCINFO) if s.uid == "0" else None
                who = nfs.owner(s) if nfs is not None and nfs.active else None
                if who:
                    nfs_count += 1
                    summary.setdefault(key, set()).add("커널 " + who)
                    continue
                summary.setdefault(key, set()).add("?")
                if nfs is not None and nfs.lockd and nfs.rpc_ok is False:
                    findings.append(self.finding(
                        reason="{}에서 리스닝하는 소켓(inode {})이 어느 프로세스의 것도 아니다 — 커널 NFS 잠금 서비스(lockd)의 "
                               "동적 포트일 수 있으나 rpcbind 등록을 확인하지 못했다 (rpcinfo 없음·실패)".format(s.describe(), s.inode),
                        next_steps="'rpcinfo'로 nlockmgr(100021) 등록 포트와 비교한다. 등록에 없으면 숨긴 프로세스의 소켓으로 보고 "
                                   "PRC-05와 함께 확인한다.",
                        evidence=[Evidence("/proc/net/" + s.proto, "{} inode {} uid {}".format(s.describe(), s.inode, s.uid))],
                        severity="info",
                    ))
                    continue
                findings.append(self.finding(
                    reason="{}에서 리스닝하는 소켓(inode {})이 어느 프로세스의 것도 아니다 — 숨긴 프로세스가 연 소켓일 수 있다 "
                           "(PRC-05 함께 확인)".format(s.describe(), s.inode),
                    next_steps="'ss -tulpn'과 비교하고, 같은 포트로 접속해 응답을 확인한다. 숨긴 수단(ld.so.preload, 커널 모듈)을 찾는다.",
                    evidence=[Evidence("/proc/net/" + s.proto, "{} inode {} uid {}".format(s.describe(), s.inode, s.uid))],
                ))
                continue
            for p, fd in s.owners:
                summary.setdefault(key, set()).add(exe_name(p) or p.name)
                why = suspicious(ctx, p)
                if not why or (p.pid, key) in reported:
                    continue
                reported.add((p.pid, key))
                findings.append(self.finding(
                    reason="{}에서 PID {} '{}'가 리스닝한다 ({})".format(s.describe(), p.pid, p.name, ", ".join(why)),
                    next_steps="이 포트로 무엇을 받는지 확인하고(접속 기록, 방화벽), 프로세스를 띄운 부모와 실행 파일을 보존한다(--out).",
                    evidence=[Evidence("/proc/{}".format(p.pid), describe(p, ctx.now)),
                              Evidence("/proc/{}/fd/{}".format(p.pid, fd), s.describe())],
                ))
        keys = sorted(summary, key=lambda k: (k.split("/")[0], int(k.split("/")[1])))
        listed = ", ".join("{}({})".format(k, "·".join(sorted(summary[k]))) for k in keys[:MAX_SCOPE])
        more = " 외 {}개".format(len(keys) - MAX_SCOPE) if len(keys) > MAX_SCOPE else ""
        notes = ""
        if kernel:
            notes += ", 커널 소켓 {}개".format(kernel)
        if nfs_count:
            notes += ", 커널 NFS 소켓 {}개".format(nfs_count)
        self.scope = "리스닝 소켓 {}개 — {}{}{}".format(len(listeners), listed or "없음", more, notes)
        return findings

    @staticmethod
    def still_listening(ctx, s):
        """열린 파일을 훑는 사이 닫힌 소켓을 빼려고 한 번 더 읽는다."""
        return any(t.inode == s.inode and t.listening for t in read_inet(ctx, s.proto))
