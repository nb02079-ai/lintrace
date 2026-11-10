"""JSON 결과 (schema 1).

텍스트 리포트와 같은 결과를 기계가 읽을 수 있게 담는다. 탐지가 없는 항목도 모두 넣는다
(텍스트 리포트의 '점검 범위'와 같은 원칙 — 무엇을 보고 무엇을 못 봤는지가 결과의 일부다).
"""
import datetime
import os
import platform
import socket

from .. import __version__, code_sha256
from .text import verdict

SCHEMA = 1
VERDICT = {"심각": "critical", "위험": "warning", "정상": "clean"}


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def first_value(ctx, path, key):
    for line in ctx.read_lines(path, missing_ok=True):
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def run_info(ctx, started):
    """실행 환경. 실제 시스템을 볼 때만 도구 자신의 환경(커널, sudo 계정)을 넣는다."""
    live = ctx.root == "/"
    host = None
    try:
        lines = ctx.read_lines("/etc/hostname", missing_ok=True)
        host = lines[0].strip() if lines else None
    except Exception:
        host = None
    if live:
        host = socket.gethostname() or host
    try:
        os_name = first_value(ctx, "/etc/os-release", "PRETTY_NAME")
    except Exception:
        os_name = None
    return {
        "host": host,
        "os": os_name,
        "kernel": os.uname().release if live else None,
        "euid": os.geteuid(),
        "sudo_user": os.environ.get("SUDO_USER") if live else None,
        "python": platform.python_version(),
        "root": ctx.root,
        "started": started,
        "finished": now_iso(),
    }


def build(ctx, checks, findings, unavailable, scopes, warnings, started, baseline=None, timeline=None):
    """checks: 실행한 항목 클래스 목록. 나머지는 __main__.run_checks()의 결과.
    baseline: 기준선 비교 사전(baseline.report_block) 또는 None.
    timeline: 사건 타임라인 사전(correlate.build_block) 또는 None."""
    skipped = dict(unavailable)
    by_check = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)
    items = []
    for cls in checks:
        mine = by_check.get(cls.id, [])
        if cls.id in skipped:
            status = "unavailable"
        elif mine:
            status = "detected"
        else:
            status = "clean"
        items.append({
            "id": cls.id, "title": cls.title, "severity": cls.severity, "attack": cls.attack,
            "status": status,
            "scope": None if cls.id in skipped else scopes.get(cls.id),
            "findings": [finding_dict(f) for f in mine],
            "error": skipped.get(cls.id),
        })
    v = VERDICT[verdict(findings)]
    if baseline is not None and v == "clean" and \
            (baseline["counts"]["added"] + baseline["counts"]["changed"]) > 0:
        v = "warning"   # 기준선에 새로 생기거나 바뀐 것이 있으면 정상이 아니다
    report = {
        "schema": SCHEMA,
        "tool": {"name": "lintrace", "version": __version__, "code_sha256": code_sha256()},
        "run": run_info(ctx, started),
        "verdict": v,
        "incomplete": bool(unavailable),
        "counts": {"checks": len(checks), "findings": len(findings), "unavailable": len(unavailable),
                   "critical": sum(1 for f in findings if f.severity == "critical"),
                   "warning": sum(1 for f in findings if f.severity == "warning"),
                   "info": sum(1 for f in findings if f.severity == "info")},
        "report_warnings": list(warnings or []),
        "checks": items,
    }
    if baseline is not None:
        report["baseline"] = baseline
    if timeline is not None:
        report["timeline"] = timeline
    return report


def finding_dict(f):
    d = f.to_dict()
    d.pop("check_id", None)  # 항목 안에 들어가므로 중복
    d.pop("title", None)
    d.pop("attack", None)
    return d
