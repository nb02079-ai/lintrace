"""systemd journal 수집기 (LOG-04·05·06, ACC-08·09 보충).

`journalctl -o json`을 실제 시스템에서만 실행해 한 번 읽는다 (없거나 --root 점검이면 비어 있음).
각 줄은 한 기록: 부팅 ID, 실시간(__REALTIME_TIMESTAMP, 마이크로초), 단조 시각(__MONOTONIC_TIMESTAMP),
프로그램(SYSLOG_IDENTIFIER·_COMM), 메시지(MESSAGE), 우선순위(PRIORITY).

실시간은 벽시계라 시각 조작·NTP 보정으로 거꾸로 갈 수 있고, 단조 시각은 부팅 뒤 흐른 시간이라 늘 증가한다.
둘을 함께 보면 '단조는 늘었는데 실시간이 뒤로 갔다'는 시각 조작을 가린다 (LOG-06).

사용법: j = journal(ctx) — 같은 Context에서는 저장된 결과를 돌려준다.
"""
import json
import shutil
import subprocess

MAX_BYTES = 200 * 1024 * 1024


class Record:
    __slots__ = ("boot", "realtime", "monotonic", "prog", "msg", "priority")

    def __init__(self, boot, realtime, monotonic, prog, msg, priority):
        self.boot = boot
        self.realtime = realtime        # 초 (float)
        self.monotonic = monotonic      # 초 (float), 부팅 기준
        self.prog = prog
        self.msg = msg
        self.priority = priority        # 0~7, 낮을수록 심각 (3 이하가 err)


class Journal:
    def __init__(self, records, available, note=""):
        self.records = records          # 읽은 순서 (보통 시간순)
        self.available = available
        self.note = note                # 못 읽은 이유 등

    def boots(self):
        """부팅 ID별 기록 (읽은 순서 유지)."""
        out = {}
        for r in self.records:
            out.setdefault(r.boot, []).append(r)
        return out

    def of_prog(self, names):
        return [r for r in self.records if r.prog in names]


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse(text):
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rt, mono = _num(d.get("__REALTIME_TIMESTAMP")), _num(d.get("__MONOTONIC_TIMESTAMP"))
        if rt is None:
            continue
        msg = d.get("MESSAGE", "")
        if isinstance(msg, list):  # 바이너리 메시지는 바이트 배열로 옴
            try:
                msg = bytes(msg).decode("utf-8", "replace")
            except (TypeError, ValueError):
                msg = ""
        records.append(Record(
            d.get("_BOOT_ID", ""), rt / 1e6, (mono / 1e6) if mono is not None else None,
            d.get("SYSLOG_IDENTIFIER") or d.get("_COMM") or "", msg, _num(d.get("PRIORITY"))))
    return records


def run_journalctl():
    exe = shutil.which("journalctl")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-o", "json", "--no-pager"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout[:MAX_BYTES].decode("utf-8", "replace")


def journal(ctx, runner=None):
    cached = getattr(ctx, "_journal", None)
    if cached is not None:
        return cached
    if runner is None:
        runner = run_journalctl if ctx.root == "/" else (lambda: None)
    text = runner()
    if text is None:
        j = Journal([], False, "journalctl 없음·실패 또는 --root 점검")
    else:
        j = Journal(parse(text), True)
    ctx._journal = j
    return j
