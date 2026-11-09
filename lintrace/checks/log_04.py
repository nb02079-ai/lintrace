"""LOG-04 로깅 데몬 중단·설정 변경.

공격자는 흔적을 남기지 않으려 로깅을 멈추거나(systemctl stop/mask rsyslog) 저장을 끈다
(journald Storage=none, rsyslog의 auth 규칙 삭제).

판정
- 심각: systemd-journald가 프로세스 목록에 없음 (systemd 시스템에서는 항상 돌아야 함)
- 심각: 설치된 rsyslog의 데몬(rsyslogd)이 없음, 또는 rsyslog·systemd-journald 유닛이 /dev/null로 마스크됨
- 위험: journald.conf(또는 .d)가 Storage=none·volatile로 디스크 저장을 끔
- 위험: rsyslog 설정이 패키지 원본과 다르고 auth·authpriv 기록 규칙이 없음
정상: /var/log/journal이 없어 journal이 메모리 전용인 것(18.04 기본값)은 범위에만 적는다.
"""
import posixpath
import re

from ..collectors.processes import processes
from .base import Check, Context, Evidence
from .persist import file_state, regular

UNIT_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]
JOURNALD_CONF = "/etc/systemd/journald.conf"
DROPINS = ["/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d", "/usr/lib/systemd/journald.conf.d"]
RSYSLOG = "/etc/rsyslog.conf"
RSYSLOG_D = "/etc/rsyslog.d"
AUTH_RULE = re.compile(r"^\s*(?:auth\b|authpriv\b|[\w,.*]*\bauth(?:priv)?\.)", re.I)
STORAGE_OFF = re.compile(r"^\s*Storage\s*=\s*(none|volatile)\b", re.I)


def masked(ctx, name):
    for d in UNIT_DIRS:
        p = posixpath.join(d, name)
        if ctx.readlink(p) is not None and ctx.realpath(p) == "/dev/null":
            return p
    return None


def installed(ctx, name):
    for d in UNIT_DIRS:
        if ctx.stat(posixpath.join(d, name)) is not None:
            return True
    return False


class Log04(Check):
    id = "LOG-04"
    title = "로깅 데몬 중단·설정 변경"
    severity = "critical"
    attack = "T1562.006"

    def run(self, ctx: Context):
        findings, notes = [], []
        comms = {p.name for p in processes(ctx).procs}
        live = ctx.root == "/"

        for svc, comm, label in (("systemd-journald.service", "systemd-journal", "systemd-journald"),
                                 ("rsyslog.service", "rsyslogd", "rsyslog")):
            m = masked(ctx, svc)
            if m:
                findings.append(self.finding(
                    reason="{} 유닛이 /dev/null로 마스크됐다 — 로깅이 꺼져 있다".format(label),
                    next_steps="'systemctl unmask {}' 후 시작하고, 누가 언제 마스크했는지 파일 ctime·명령 기록으로 본다.".format(label),
                    evidence=[Evidence(m, "→ /dev/null")]))
                continue
            if label == "systemd-journald":
                if live and not any(c.startswith("systemd-journal") for c in comms):
                    findings.append(self.finding(
                        reason="systemd-journald가 돌고 있지 않다 — systemd 시스템에서는 항상 실행돼야 한다",
                        next_steps="'systemctl status systemd-journald'로 멈춘 이유를 보고, 멈춘 시각 전후의 활동을 확인한다.",
                        evidence=[Evidence("/proc", "프로세스 목록에 systemd-journald 없음")]))
            elif installed(ctx, svc) and live and "rsyslogd" not in comms:
                findings.append(self.finding(
                    reason="rsyslog가 설치돼 있는데 rsyslogd가 돌고 있지 않다",
                    next_steps="'systemctl status rsyslog'로 멈춘 이유를 보고, 멈춘 시각 전후의 활동을 확인한다.",
                    evidence=[Evidence("/proc", "프로세스 목록에 rsyslogd 없음")]))

        storage = []
        for path in [JOURNALD_CONF] + [posixpath.join(d, n) for d in DROPINS for n in ctx.list_dir(d)
                                       if n.endswith(".conf")]:
            for no, line in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
                if STORAGE_OFF.match(line):
                    storage.append(Evidence(path, "{}행: {}".format(no, line.strip())))
        if storage:
            findings.append(self.finding(
                reason="journald가 로그를 디스크에 저장하지 않도록 설정돼 있다 (Storage=none·volatile) — 재부팅하면 기록이 사라진다",
                next_steps="의도한 설정인지 확인한다. 아니면 Storage=persistent로 두고 'systemctl restart systemd-journald'.",
                evidence=storage, severity="warning"))

        if regular(ctx, RSYSLOG):
            state, pkg = file_state(ctx, RSYSLOG)
            files = [RSYSLOG] + [posixpath.join(RSYSLOG_D, n) for n in ctx.list_dir(RSYSLOG_D) if n.endswith(".conf")]
            has_auth = any(AUTH_RULE.match(l) for f in files for l in ctx.read_lines(f, missing_ok=True))
            changed = state == "modified" or any(file_state(ctx, posixpath.join(RSYSLOG_D, n))[0] == "modified"
                                                 for n in ctx.list_dir(RSYSLOG_D) if n.endswith(".conf"))
            if changed and not has_auth:
                findings.append(self.finding(
                    reason="rsyslog 설정이 패키지 원본과 다르고 인증 로그(auth·authpriv) 기록 규칙이 없다 — 인증 기록을 끈 흔적일 수 있다",
                    next_steps="설정을 원본과 비교하고(dpkg 원본), auth·authpriv를 /var/log/auth.log에 쓰는 규칙을 되살린다.",
                    evidence=[Evidence(RSYSLOG, "패키지({}) 원본과 다름, auth 규칙 없음".format(pkg or "?"))],
                    severity="warning"))

        if not ctx.exists("/var/log/journal"):
            notes.append("journal 메모리 전용(/var/log/journal 없음 — 재부팅 시 사라짐)")
        self.scope = "rsyslogd {}, systemd-journald {}{}".format(
            "실행 중" if "rsyslogd" in comms else "없음",
            "실행 중" if any(c.startswith("systemd-journal") for c in comms) else "없음",
            " — " + ", ".join(notes) if notes else "")
        return findings
