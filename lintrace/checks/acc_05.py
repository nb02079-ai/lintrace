"""ACC-05 관리자 그룹 구성원 이상.

root와 같은 권한을 주는 그룹이 있다. docker(docker run -v /:/mnt), lxd(특권 컨테이너), disk(디스크 장치를
직접 읽고 씀), shadow(비밀번호 해시 읽기), root 그룹. 이런 그룹에 넣는 것은 sudoers를 건드리지 않는
권한 상승 통로다.

판정 (위험)
- root와 같은 권한을 주는 그룹(root·shadow·disk·docker·lxd)의 구성원인데 관리자 그룹(sudo·admin·wheel)이
  아닌 계정 — 이미 관리자인 계정의 lxd 등은 새 권한이 아니다 (Ubuntu 설치 프로그램이 첫 계정에 넣음)
- 시스템 계정(UID 1~999)이 관리자 그룹 구성원
사람 계정의 관리자 그룹 소속은 판정하지 않고 점검 범위에 목록으로 보여준다.
sudoers에도 root 셸 권한 규칙이 있는 계정이면 근거에 'ACC-06에서도 탐지'를 붙인다.
"""
from ..collectors.accounts import accounts
from .acc_06 import _Sudoers
from .base import Check, Context, Evidence, Unavailable

ROOT_EQUIVALENT = {
    "root": "root 그룹 파일에 쓸 수 있음",
    "shadow": "/etc/shadow의 비밀번호 해시를 읽을 수 있음",
    "disk": "디스크 장치를 직접 읽고 써 모든 파일을 다룰 수 있음",
    "docker": "'docker run -v /:/mnt'로 root 파일시스템을 다룰 수 있음",
    "lxd": "특권 컨테이너로 root 파일시스템을 다룰 수 있음",
}
ADMIN = ("sudo", "admin", "wheel")


def sudo_rule_users(ctx):
    """sudoers에서 root 셸 권한 규칙을 가진 계정 (ACC-06과 같은 해석)."""
    out = set()
    try:
        if ctx.stat("/etc/sudoers") is None:
            return out
        s = _Sudoers(ctx)
        s.parse_file("/etc/sudoers")
        for _, _, text in s.rules:
            result = s.analyze(text)
            if result is None:
                continue
            users, hits, nopasswd, _ = result
            if hits["all"] or hits["shell"] or hits["escape"] or hits["write"] or nopasswd:
                out.update(users)
    except Unavailable:
        pass
    return out


class Acc05(Check):
    id = "ACC-05"
    title = "관리자 그룹 구성원 이상"
    severity = "warning"
    attack = "T1098"

    def run(self, ctx: Context):
        acc = accounts(ctx)
        by_name = {u.name: u for u in acc.users}
        admins = set()
        for g in ADMIN:
            grp = acc.group_by_name(g)
            if grp:
                admins.update(acc.members(grp))
        sudo_users = sudo_rule_users(ctx)

        findings, listed = [], []
        for gname in list(ROOT_EQUIVALENT) + list(ADMIN):
            grp = acc.group_by_name(gname)
            if not grp:
                continue
            for member in acc.members(grp):
                user = by_name.get(member)
                if member == "root" or (user is not None and user.uid == 0):
                    continue  # UID 0 계정은 이미 root (ACC-01이 본다)
                if gname in ROOT_EQUIVALENT and member not in admins:
                    reason = "'{}' 계정이 '{}' 그룹 구성원이다 — {} (관리자 그룹이 아니어서 새로 얻는 root 권한)".format(
                        member, gname, ROOT_EQUIVALENT[gname])
                elif gname in ADMIN and user is not None and user.is_system:
                    reason = "시스템 계정 '{}'(UID {})이 관리자 그룹 '{}' 구성원이다".format(member, user.uid, gname)
                else:
                    listed.append("{}({})".format(gname, member))
                    continue
                ev = [Evidence("/etc/group", "{}행: {}".format(grp.lineno, grp.line))]
                if member in sudo_users:
                    ev.append(Evidence("/etc/sudoers", "이 계정은 sudoers에도 root 권한 규칙이 있다 (ACC-06에서도 탐지)"))
                findings.append(self.finding(
                    reason=reason,
                    next_steps="이 계정이 그룹에 들어간 시점과 이유를 확인하고(usermod·gpasswd 기록, /etc/group 변경 시각), "
                               "필요 없으면 'gpasswd -d {} {}'로 뺀다.".format(member, gname),
                    evidence=ev,
                ))
        self.scope = "그룹 {}개, 관리자 그룹 구성원: {}".format(len(acc.groups), ", ".join(listed) or "없음")
        return findings
