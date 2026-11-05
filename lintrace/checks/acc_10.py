"""ACC-10 sshd_config 위험 설정.

sshd_config와 Include된 파일(24.04: sshd_config.d/*.conf)을 ACC-07과 같은 해석기로 읽는다.
sshd는 같은 지시어가 여러 번 나오면 처음 값을 쓰므로, Match 블록 밖의 첫 값을 실제 설정으로 본다.
Match 블록 안의 위험 값은 조건부 설정으로 따로 표시한다.

판정
- 위험: PermitEmptyPasswords yes (빈 비밀번호 로그인), AuthorizedKeysFile이 홈의 .ssh 밖
        (공격자가 쓸 수 있는 곳에 키 파일을 두는 뒷문)
- 참고: PermitRootLogin yes (root 비밀번호 로그인), PermitUserEnvironment yes (키 파일의 environment=로
        LD_PRELOAD 등을 넣을 수 있음)
"""
from .acc_07 import SSHD_CONFIG, _SshdConfig, is_standard
from .base import Check, Context, Evidence

RULES = {
    "permitemptypasswords": ("yes", "warning", "빈 비밀번호 계정이 로그인할 수 있다"),
    "permitrootlogin": ("yes", "info", "root가 비밀번호로 SSH 로그인할 수 있다"),
    "permituserenvironment": ("yes", "info", "authorized_keys의 environment=로 환경변수(LD_PRELOAD 등)를 넣을 수 있다"),
}


class Acc10(Check):
    id = "ACC-10"
    title = "sshd_config 위험 설정"
    severity = "info"
    attack = "T1098"

    def run(self, ctx: Context):
        if ctx.stat(SSHD_CONFIG, follow=True) is None:
            self.scope = "sshd 설정 없음"
            return []
        cfg = _SshdConfig(ctx)
        cfg.parse(SSHD_CONFIG)
        findings, effective = [], set()
        for path, no, line, key, value, in_match in cfg.directives:
            first = False
            if not in_match and key not in effective:
                effective.add(key)
                first = True
            if not first and not in_match:
                continue  # 처음 값이 이미 정해져 이 줄은 쓰이지 않는다
            where = " (Match 블록 안 — 조건에 맞는 접속에만 적용)" if in_match else ""
            if key in RULES and value.split() and value.split()[0].lower() == RULES[key][0]:
                _, severity, why = RULES[key]
                findings.append(self.finding(
                    reason="{} {}: {}{}".format(line.split()[0], value, why, where),
                    next_steps="이 설정이 필요한지 확인하고, 아니면 기본값으로 되돌린 뒤 'systemctl reload ssh'. "
                               "설정 파일이 바뀐 시점과 그 뒤 접속 기록을 함께 본다.",
                    evidence=[Evidence(path, "{}행: {}".format(no, line))],
                    severity=severity,
                ))
            elif key == "authorizedkeysfile":
                odd = [v for v in value.split() if not is_standard(v)]
                if odd:
                    findings.append(self.finding(
                        reason="AuthorizedKeysFile이 홈의 .ssh 밖도 키 파일로 쓴다: {}{} — 공격자가 쓸 수 있는 곳이면 "
                               "키를 넣어 로그인할 수 있는 뒷문".format(", ".join(odd), where),
                        next_steps="그 경로의 키 파일과 권한을 확인한다 (ACC-07이 해당 파일의 키를 함께 보여준다).",
                        evidence=[Evidence(path, "{}행: {}".format(no, line))],
                        severity="warning",
                    ))
        self.scope = "설정 파일 {}개, 지시어 {}개".format(len(cfg.visited), len(cfg.directives))
        return findings
