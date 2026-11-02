"""PER-05 /etc/ld.so.preload 존재.

/etc/ld.so.preload에 적힌 라이브러리는 모든 프로그램이 시작할 때 먼저 불려 들어간다.
루트킷이 프로세스·파일을 숨기는 대표적인 방법이며, 정상 서버에는 이 파일이 거의 없다.
같은 목적으로 쓰일 수 있는 라이브러리 경로 설정(/etc/ld.so.conf)도 함께 본다.

판정
- 심각: ld.so.preload에 라이브러리가 하나라도 적혀 있음
        (임시 폴더·숨김 경로·없는 파일이면 이유에 따로 표시)
- 위험: ld.so.preload 파일 자체를 다른 사용자가 바꿀 수 있음 (비어 있어도)
- 위험: ld.so.conf(.d)가 등록한 라이브러리 폴더를 다른 사용자가 쓸 수 있거나,
        그 폴더가 임시 폴더·홈 아래에 있음 (라이브러리 바꿔치기 통로)
- 위험: ld.so.conf(.d) 설정 파일을 다른 사용자가 바꿀 수 있음
- 참고: ld.so.preload가 있지만 비어 있거나 주석뿐

immutable 속성 확인은 FS-09가 맡는다.
"""
import fnmatch
import posixpath
import re
import stat

from .. import timefmt
from .base import Check, Context, Evidence

PRELOAD = "/etc/ld.so.preload"
LD_CONF = "/etc/ld.so.conf"
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
USER_DIRS = ("/home/",) + TEMP_DIRS
MAX_DEPTH = 8


def preload_entries(lines):
    """ld.so.preload는 공백이나 ':'로 라이브러리를 나눈다. [(줄 번호, 라이브러리)]"""
    out = []
    for no, raw in enumerate(lines, start=1):
        s = raw.split("#", 1)[0].strip()
        for lib in re.split(r"[\s:]+", s):
            if lib:
                out.append((no, lib))
    return out


def odd_location(path):
    """임시 폴더나 숨김 경로면 그 설명을 돌려준다."""
    if path.startswith(TEMP_DIRS):
        return "임시 폴더"
    parts = [p for p in path.split("/") if p]
    if any(p.startswith(".") and p not in (".", "..") for p in parts):
        return "숨김 경로"
    return None


def writable_by_others(st):
    """root 외 계정이 바꿀 수 있는지 (소유자가 root가 아니거나 그룹·다른 사용자 쓰기 권한)."""
    if st.st_uid != 0:
        return True
    if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
        return False  # /tmp처럼 스티키 비트가 있으면 남의 파일을 바꿀 수 없다
    return bool(st.st_mode & 0o022)


def describe_mode(st):
    return "권한 {:o}, 소유자 UID {}".format(stat.S_IMODE(st.st_mode), st.st_uid)


class Per05(Check):
    id = "PER-05"
    title = "/etc/ld.so.preload 존재"
    severity = "critical"
    attack = "T1574.006"

    def run(self, ctx: Context):
        findings = []
        libs = None
        st = ctx.stat(PRELOAD)
        if st is not None:
            finding, libs = self.check_preload(ctx, st)
            if finding:
                findings.append(finding)

        dirs, conf_files = self.read_ld_conf(ctx)
        findings += self.check_lib_dirs(ctx, dirs, conf_files)

        preload_text = "preload 없음" if libs is None else "preload 라이브러리 {}개".format(libs)
        self.scope = "{}, 라이브러리 경로 {}개".format(preload_text, len(dirs))
        return findings

    def check_preload(self, ctx, st):
        evidence = []
        if stat.S_ISLNK(st.st_mode):
            evidence.append(Evidence(PRELOAD, "심볼릭 링크 → {}".format(ctx.readlink(PRELOAD))))
            st = ctx.stat(PRELOAD, follow=True)
            if st is None:
                return None, 0  # 대상이 없는 링크: 동적 링커도 읽지 못한다
        entries = preload_entries(ctx.read_lines(PRELOAD))  # 일반 파일이 아니면 Unavailable
        critical, warning = [], []

        for no, lib in entries:
            lst = ctx.stat(lib, follow=True) if lib.startswith("/") else None
            if not lib.startswith("/"):
                state = "경로 없이 이름만 적힘"
            elif lst is None:
                state = "파일 없음"
            else:
                state = "있음, " + describe_mode(lst)
            evidence.append(Evidence(PRELOAD, "{}행: {} ({})".format(no, lib, state)))
        if entries:
            text = "모든 프로그램에 라이브러리 {}개가 강제로 불려 들어간다".format(len(entries))
            notes = []
            for _, lib in entries:
                where = odd_location(lib)
                if where:
                    notes.append("{}: {}".format(where, lib))
            if notes:
                text += " — " + ", ".join(notes)
            critical.append(text)

        if writable_by_others(st):
            warning.append("{}를 다른 사용자가 바꿀 수 있다 ({})".format(PRELOAD, describe_mode(st)))

        evidence.append(Evidence(PRELOAD, "파일 변경: {}".format(timefmt.describe(st.st_mtime, ctx.now)[0])))
        if critical:
            severity = "critical"
        elif warning:
            severity = "warning"
        else:
            severity = "info"
        conditions = critical + warning or ["파일은 있지만 적힌 라이브러리가 없다"]
        return self.finding(
            reason="{}: {}".format(PRELOAD, "; ".join(conditions)),
            next_steps="적힌 라이브러리가 어느 패키지에 속하는지(dpkg -S) 확인하고, 없거나 낯선 라이브러리면 "
                       "루트킷을 의심해 다른 시스템에서 디스크를 분석한다. 감염된 시스템의 ps·ls 결과는 믿을 수 없다.",
            evidence=evidence,
            severity=severity,
        ), len(entries)

    def read_ld_conf(self, ctx):
        """ld.so.conf와 include된 파일에서 라이브러리 폴더를 모은다.

        돌려주는 값: ([(폴더, 설정 파일, 줄 번호)], [읽은 설정 파일])
        """
        dirs, files, visited = [], [], set()

        def parse(path, depth):
            if depth > MAX_DEPTH or path in visited:
                return
            visited.add(path)
            lines = ctx.read_lines(path, missing_ok=True)
            if ctx.stat(path, follow=True) is not None:
                files.append(path)
            for no, raw in enumerate(lines, start=1):
                s = raw.split("#", 1)[0].strip()
                if not s:
                    continue
                if s.startswith("include ") or s.startswith("include\t"):
                    for pattern in s.split()[1:]:
                        if not pattern.startswith("/"):
                            pattern = posixpath.join(posixpath.dirname(path), pattern)
                        directory, name = posixpath.split(pattern)
                        if any(c in name for c in "*?["):
                            for entry in ctx.list_dir(directory):
                                if fnmatch.fnmatch(entry, name):
                                    parse(posixpath.join(directory, entry), depth + 1)
                        else:
                            parse(pattern, depth + 1)
                    continue
                if s.startswith("hwcap"):
                    continue
                for d in re.split(r"[\s,:=]+", s):
                    if d.startswith("/"):
                        dirs.append((posixpath.normpath(d), path, no))

        parse(LD_CONF, 0)
        return dirs, files

    def check_lib_dirs(self, ctx, dirs, conf_files):
        findings = []
        for path in conf_files:
            st = ctx.stat(path, follow=True)
            if st is not None and writable_by_others(st):
                findings.append(self.finding(
                    reason="라이브러리 경로 설정 {}를 다른 사용자가 바꿀 수 있다 ({})".format(path, describe_mode(st)),
                    next_steps="설정 파일의 권한을 root 644로 되돌리고, 내용에 낯선 폴더가 추가되지 않았는지 확인한다.",
                    evidence=[Evidence(path, describe_mode(st)),
                              Evidence(path, "파일 변경: {}".format(timefmt.describe(st.st_mtime, ctx.now)[0]))],
                    severity="warning",
                ))
        seen = set()
        for d, src, no in dirs:
            if d in seen:
                continue
            seen.add(d)
            st = ctx.stat(d, follow=True)
            if st is None:
                continue  # 없는 폴더는 동적 링커도 건너뛴다
            problems = []
            if (d + "/").startswith(USER_DIRS):
                problems.append("사용자 영역(홈·임시 폴더) 안에 있다")
            if writable_by_others(st):
                problems.append("다른 사용자가 쓸 수 있다 ({})".format(describe_mode(st)))
            if problems:
                findings.append(self.finding(
                    reason="라이브러리 경로 {}: {} — 이 폴더에 같은 이름의 라이브러리를 넣으면 프로그램이 그것을 "
                           "불러들일 수 있다".format(d, ", ".join(problems)),
                    next_steps="이 경로가 왜 등록됐는지 확인하고, 폴더 안 라이브러리가 어느 패키지에 속하는지 확인한다.",
                    evidence=[Evidence(src, "{}행: {}".format(no, d))],
                    severity="warning",
                ))
        return findings
