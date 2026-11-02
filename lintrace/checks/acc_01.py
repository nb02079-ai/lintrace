"""ACC-01 root 외 UID 0 계정 존재 — 다른 항목을 만들 때 참고하는 예시 구현."""
from .base import Check, Context, Evidence

# 비밀번호 칸에 이 값들만 있으면 비밀 정보가 아니므로 그대로 보여준다
# (x: shadow에 저장, *·!·!!: 잠김, 빈 값: 비밀번호 없음 — 빈 값은 그 자체가 단서)
NOT_SECRET = {"x", "*", "!", "!!", ""}


def mask_passwd_line(line: str) -> str:
    """/etc/passwd 한 줄에서 비밀번호 해시를 가린다. 리포트는 공유되는 문서이기 때문."""
    parts = line.split(":")
    if len(parts) >= 2 and parts[1] not in NOT_SECRET:
        parts[1] = "<가림>"
    return ":".join(parts)


class Acc01(Check):
    id = "ACC-01"
    title = "root 외 UID 0 계정 존재"
    severity = "critical"
    attack = "T1136"

    def run(self, ctx: Context):
        findings = []
        for lineno, line in enumerate(ctx.read_lines("/etc/passwd"), start=1):
            parts = line.split(":")
            if len(parts) < 7 or line.startswith("#"):
                continue
            name, uid = parts[0], parts[2]
            if uid == "0" and name != "root":
                findings.append(self.finding(
                    reason="'{}' 계정의 UID가 0이라 root와 같은 권한을 가진다.".format(name),
                    next_steps="계정 생성 시각(auth.log의 useradd), 이 계정의 로그인 기록, 홈 디렉터리 내용을 확인한다.",
                    evidence=[Evidence("/etc/passwd", "{}행: {}".format(lineno, mask_passwd_line(line)))],
                ))
        return findings
