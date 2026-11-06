"""2-C 지속성 항목(PER-02·03·04·06·07·08·09)과 FS-04·05가 함께 쓰는 도우미.

- file_state(): 패키지 원본과 비교한 상태 — 'unpackaged'(패키지 밖) / 'modified'(원본과 다름) / 'same' / 'unknown'
  (md5sums·conffiles 기록이 없는 패키지 파일). 시간 원칙에 따라 변경 시각은 판정에 쓰지 않는다.
- owner_issue(): root가 실행하는 파일을 일반 사용자가 소유하거나 쓸 수 있는지 (권한 상승 경로)
- target_issues(): 실행 대상 파일의 위치·소속
- group(): 같은 폴더의 여러 파일을 한 건으로 묶는다 (2026-11-06 결정 5)
"""
import hashlib
import posixpath
import stat

from .. import timefmt
from ..collectors.packages import packages
from .base import Evidence, Unavailable
from .scriptscan import TEMP_DIRS, hidden_system_path

RANK = {"info": 0, "warning": 1, "critical": 2}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox"}
INTERPRETERS = ("python", "perl", "php", "ruby", "node", "lua", "tclsh", "wish")
NET_TOOLS = {"nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat"}
HOMES = ("/home/", "/root/")


def md5_file(ctx, path):
    h = hashlib.md5()
    try:
        with open(ctx.path(path), "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def file_state(ctx, path):
    """(상태, 패키지). 링크는 따라간 실제 파일로 본다."""
    db = packages(ctx)
    if not db.available:
        return "unknown", None
    real = ctx.realpath(path)
    pkg = db.owner(path) or db.owner(real)
    if pkg is None:
        div = db.diversion(path) or db.diversion(real)
        if div:
            return "unknown", div[1]
        return "unpackaged", None
    rec = db.conffile(path) or db.conffile(real) or db.md5(path) or db.md5(real)
    if rec is None:
        return "unknown", pkg
    actual = md5_file(ctx, real)
    if actual is None:
        return "unknown", pkg
    return ("same" if actual == rec[0] else "modified"), pkg


def state_text(state, pkg):
    return {"unpackaged": "패키지에 속하지 않음",
            "modified": "패키지({}) 원본과 다름".format(pkg),
            "same": "패키지({}) 원본과 같음".format(pkg),
            "unknown": "패키지({}) — 원본 해시 기록 없음".format(pkg) if pkg else "패키지 정보 없음"}[state]


def uid_name(ctx, uid):
    for line in ctx.read_lines("/etc/passwd", missing_ok=True):
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == str(uid):
            return parts[0]
    return "UID {}".format(uid)


def owner_issue(ctx, path):
    """root가 실행·읽는 파일을 다른 사용자가 바꿀 수 있으면 설명, 아니면 None."""
    try:
        st = ctx.stat(path, follow=True)
    except Unavailable:
        return None
    if st is None:
        return None
    if st.st_uid != 0:
        return "{}의 소유자가 일반 사용자 {}다 — 그 사용자가 내용을 바꿔 root 권한으로 실행시킬 수 있다".format(
            path, uid_name(ctx, st.st_uid))
    if st.st_mode & 0o002 or (st.st_mode & 0o020 and st.st_gid != 0):
        return "{}를 다른 사용자가 쓸 수 있다 (권한 {:o}, 그룹 GID {})".format(path, stat.S_IMODE(st.st_mode), st.st_gid)
    return None


def is_shell_like(path):
    name = posixpath.basename(path)
    return name in SHELLS or name in NET_TOOLS or name.startswith(INTERPRETERS)


def target_issues(ctx, target, runs_as_root=True):
    """실행 대상 파일의 문제. [(위험도, 설명)] — 문제 없으면 빈 목록."""
    out = []
    if not target.startswith("/"):
        return out
    if target.startswith(TEMP_DIRS):
        out.append(("critical", "실행 대상 {}가 임시 폴더에 있다".format(target)))
    elif hidden_system_path(target):
        out.append(("critical", "실행 대상 {}가 시스템 영역의 숨김 경로에 있다".format(target)))
    elif target.startswith(HOMES):
        out.append(("critical" if runs_as_root else "warning",
                    "실행 대상 {}가 홈 폴더(/home·/root)에 있다".format(target)))
    try:
        st = ctx.stat(target, follow=True)
    except Unavailable:
        st = None
    if st is None:
        if not target.startswith(HOMES + TEMP_DIRS):
            out.append(("warning", "실행 대상 {}가 없다 (지워졌거나 읽을 수 없음)".format(target)))
        return out
    if packages(ctx).available and file_state(ctx, target)[0] == "unpackaged" and not out:
        out.append(("warning", "실행 대상 {}가 패키지에 속하지 않는다".format(target)))
    if runs_as_root:
        issue = owner_issue(ctx, target)
        if issue:
            out.append(("critical", issue))
    return out


def packaged_binary(ctx, target):
    """셸·인터프리터·nc가 아닌 패키지 실행 파일인지 (생성 파일 예외 판단)."""
    return (target.startswith("/") and not is_shell_like(ctx.realpath(target)) and not is_shell_like(target)
            and file_state(ctx, target)[0] in ("same", "unknown") and packages(ctx).owner(ctx.realpath(target)) is not None)


def file_evidence(ctx, path, state, pkg):
    ev = [Evidence(path, state_text(state, pkg))]
    try:
        st = ctx.stat(path)
    except Unavailable:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        ev.append(Evidence(path, "링크 → {}".format(ctx.readlink(path))))
    elif st is not None:
        when, _ = timefmt.describe(st.st_mtime, ctx.now)
        ev.append(Evidence(path, "소유자 {}, 권한 {:o}, 내용 변경: {}".format(
            uid_name(ctx, st.st_uid), stat.S_IMODE(st.st_mode), when)))
    return ev


class Item:
    """한 파일의 판정 결과."""

    def __init__(self, path, conditions, evidence):
        self.path = path
        self.conditions = conditions      # [(위험도, 설명)]
        self.evidence = evidence

    @property
    def severity(self):
        return max((c[0] for c in self.conditions), key=RANK.get)


def group(check, items, next_steps, label):
    """폴더별로 한 건. label: '서비스 유닛' 같은 파일 종류 이름."""
    by_dir = {}
    for it in items:
        if it.conditions:
            by_dir.setdefault(posixpath.dirname(it.path), []).append(it)
    findings = []
    for d in sorted(by_dir):
        its = sorted(by_dir[d], key=lambda x: (-RANK[x.severity], x.path))
        sev = its[0].severity
        if len(its) == 1:
            reason = "{} {}: {}".format(label, its[0].path, "; ".join(c[1] for c in its[0].conditions))
        else:
            reason = "{}의 {} {}개: {}".format(d, label, len(its), " / ".join(
                "{}({})".format(posixpath.basename(x.path), "; ".join(c[1] for c in x.conditions)) for x in its))
        ev = []
        for it in its:
            ev += it.evidence
        findings.append(check.finding(reason=reason, next_steps=next_steps, evidence=ev[:20], severity=sev))
    return findings


def max_sev(conditions):
    return max((c[0] for c in conditions), key=RANK.get) if conditions else None


def homes(ctx):
    """[(사용자, 홈)] — /etc/passwd의 홈 중 실제로 있는 폴더 (root 포함, 중복 제거)."""
    out, seen = [], set()
    for line in ctx.read_lines("/etc/passwd", missing_ok=True):
        parts = line.split(":")
        if len(parts) < 7 or not parts[5].startswith("/") or parts[5] in ("/", "/nonexistent"):
            continue
        home = parts[5].rstrip("/")
        if home in seen:
            continue
        try:
            st = ctx.stat(home, follow=True)
        except Unavailable:
            continue
        if st is not None and stat.S_ISDIR(st.st_mode):
            seen.add(home)
            out.append((parts[0], home))
    return out


def unique_dirs(ctx, dirs):
    """usrmerge로 같은 폴더를 가리키는 경로(/lib ↔ /usr/lib)는 한 번만."""
    out, seen = [], set()
    for d in dirs:
        real = ctx.realpath(d)
        if real in seen:
            continue
        try:
            st = ctx.stat(d, follow=True)
        except Unavailable:
            continue
        if st is not None and stat.S_ISDIR(st.st_mode):
            seen.add(real)
            out.append(d)
    return out


def regular(ctx, path):
    try:
        st = ctx.stat(path, follow=True)
    except Unavailable:
        return False
    return st is not None and stat.S_ISREG(st.st_mode)


def executable(ctx, path):
    try:
        st = ctx.stat(path, follow=True)
    except Unavailable:
        return False
    return st is not None and stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)
