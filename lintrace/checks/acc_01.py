"""ACC-01 root 외 UID 0 계정 존재 — 다른 항목을 만들 때 참고하는 예시 구현."""
from .base import Check, Context, Evidence


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
                    reason=f"'{name}' 계정의 UID가 0이라 root와 같은 권한을 가진다.",
                    next_steps="계정 생성 시각(auth.log의 useradd), 이 계정의 로그인 기록, 홈 디렉터리 내용을 확인한다.",
                    evidence=[Evidence("/etc/passwd", f"{lineno}행: {line}")],
                ))
        return findings
