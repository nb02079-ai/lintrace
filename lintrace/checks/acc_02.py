"""ACC-02 정상 도구로 만들지 않은 흔적이 있는 계정.

useradd·adduser는 /etc/passwd, /etc/shadow, /etc/group을 함께 맞춘다. 공격자가
'echo ... >> /etc/passwd'처럼 직접 계정을 넣으면 이 셋이 어긋난다. 시각이나 로그 보존 기간에
기대지 않는 흔적이라, 로그를 비운 서버에서도 쓸 수 있다.
(원래 정의 "생성 기록이 없는 계정"은 로그 순환이 지나면 정상 계정까지 모두 걸려서 바꿨다 — 2026-11-05)

판정 (위험)
- passwd에 있는데 shadow에 없는 계정 (또는 그 반대)
- 기본 그룹 GID가 /etc/group에 없는 계정
인증 로그에 'new user: name=…' 기록이 있으면 근거로 붙인다.
"""
import re

from ..collectors.accounts import accounts
from ..collectors.authlog import auth_log
from .acc_01 import mask_passwd_line
from .base import Check, Context, Evidence, Unavailable

NEW_USER = re.compile(r"new user: name=([^,\s]+)")


class Acc02(Check):
    id = "ACC-02"
    title = "정상 도구로 만들지 않은 흔적이 있는 계정"
    severity = "warning"
    attack = "T1136.001"

    def run(self, ctx: Context):
        acc = accounts(ctx)
        shadow = acc.shadow()
        gids = {g.gid for g in acc.groups}
        created = self.creation_records(ctx)

        findings = []
        for u in acc.users:
            problems = []
            if acc.has_shadow and u.name not in shadow:
                problems.append("/etc/shadow에 항목이 없다")
            if acc.has_group and u.gid not in gids:
                problems.append("기본 그룹 GID {}가 /etc/group에 없다".format(u.gid))
            if problems:
                ev = [Evidence("/etc/passwd", "{}행: {}".format(u.lineno, mask_passwd_line(u.line)))]
                ev += [Evidence(e.source, "{}: {}".format(e.where(), e.raw)) for e in created.get(u.name, [])[:3]]
                findings.append(self.finding(
                    reason="'{}' 계정: {} — useradd 같은 정상 도구는 계정 파일을 함께 맞추므로, "
                           "파일을 직접 고쳐 넣은 계정일 수 있다".format(u.name, ", ".join(problems)),
                    next_steps="이 계정이 언제 어떻게 생겼는지 확인한다 (/etc/passwd 변경 시각, 명령 기록의 "
                               "'>> /etc/passwd'·vipw, 이 계정의 로그인 기록). 필요 없는 계정이면 잠그고 조사한다.",
                    evidence=ev,
                ))
        names = {u.name for u in acc.users}
        for name in sorted(set(shadow) - names):
            pw, no = shadow[name]
            findings.append(self.finding(
                reason="'{}' 계정: /etc/shadow에만 있고 /etc/passwd에는 없다 — 지운 계정의 흔적이거나 "
                       "파일을 직접 고친 흔적".format(name),
                next_steps="계정이 지워진 시점과 이유를 확인한다 (userdel 기록, 명령 기록).",
                evidence=[Evidence("/etc/shadow", "{}행: {}:<가림>".format(no, name))],
            ))
        self.scope = "계정 {}개, {}, 그룹 {}개".format(
            len(acc.users), "shadow {}개".format(len(shadow)) if acc.has_shadow else "shadow 없음 (비교 생략)", len(acc.groups))
        return findings

    @staticmethod
    def creation_records(ctx):
        out = {}
        try:
            log = auth_log(ctx)
        except Unavailable:
            return out
        for e in log.entries:
            m = NEW_USER.search(e.msg)
            if m:
                out.setdefault(m.group(1), []).append(e)
        return out
