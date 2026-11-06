"""FS-02 패키지에 속하지 않거나 비정상 위치의 SUID·SGID 파일.

SUID 파일은 누가 실행하든 파일 소유자(대개 root) 권한으로 돈다. 공격자는 root를 얻은 뒤
'cp /bin/bash /var/tmp/.b; chmod u+s'로 돌아올 문을 만들고, 관리자가 find·vim 같은
프로그램에 SUID를 잘못 붙이면 그 자체가 권한 상승 통로가 된다.

판정
- 심각: 사용자 영역(/tmp, /var/tmp, /dev/shm, /home, /var/www)이나 숨김 경로에 있음
- 심각: 셸을 복사한 파일 (내용 해시가 시스템 셸과 같음)
- 심각: 셸 탈출·파일 읽기쓰기가 되는 프로그램에 root SUID가 붙음 (패키지 소속과 무관 —
        패키지는 이런 프로그램을 SUID로 설치하지 않는다). 그룹 SUID만 있거나 root가 아닌
        계정 소유면 위험.
- 위험: 어떤 패키지에도 속하지 않는 SUID·SGID 파일
- (탐지 아님) 패키지에 속한 표준 SUID·SGID 파일은 점검 범위에 개수로 표시

검색 범위: 파일시스템 전체 (collectors/filewalk.py — FS-03·08과 한 번의 훑기를 같이 쓴다).
/proc, /sys, /run, /dev(/dev/shm은 포함), /snap, 네트워크·가상 파일시스템은 뺀다. 링크는 따라가지 않는다.
패키지 소속은 /var/lib/dpkg/info/*.list로 판단하고, /bin → /usr/bin 같은 usrmerge 경로를 맞춘다.
패키지 원본과 해시가 다른지(바꿔치기)는 FS-04가 본다.
SUID를 붙이면 mtime은 그대로이고 ctime만 바뀌므로 근거에 둘 다 보인다.
"""
import os
import posixpath
import re
import stat

from .. import timefmt
from ..collectors.filewalk import EXTRA_ROOTS, SKIP_FSTYPES, STATIC_EXCLUDE, filewalk, unescape_mount  # noqa: F401
from ..collectors.packages import packages, path_aliases  # noqa: F401 (path_aliases는 테스트가 씀)
from .base import Check, Context, Evidence, Unavailable

USER_AREAS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/var/www/")
SHELL_BINARIES = ["/bin/bash", "/bin/dash", "/bin/sh", "/bin/zsh", "/usr/bin/zsh", "/bin/ksh",
                  "/usr/bin/ksh", "/bin/busybox", "/usr/bin/fish", "/bin/tcsh", "/bin/csh", "/bin/mksh"]
# GTFOBins의 'SUID' 기능이 있는 프로그램 (표준 SUID인 su·sudo·passwd·mount 등은 넣지 않는다)
SUID_ESCAPE = {
    # 셸·인터프리터
    "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox",
    "python", "perl", "ruby", "php", "node", "lua", "tclsh", "wish", "expect",
    "awk", "gawk", "mawk", "nawk",
    # 편집기·페이저
    "vi", "vim", "rvim", "view", "vimdiff", "nano", "pico", "ed", "emacs", "less", "more",
    # 파일 읽기·쓰기
    "cat", "head", "tail", "cut", "dd", "tee", "cp", "mv", "install", "chmod", "chown",
    "base64", "base32", "xxd", "od", "hexdump", "sort", "uniq", "diff", "comm", "fold", "nl",
    "paste", "rev", "tac", "sed", "grep", "strings",
    # 명령 실행
    "find", "xargs", "env", "nice", "ionice", "timeout", "stdbuf", "setarch", "chroot", "taskset",
    "strace", "gdb", "nohup", "time", "watch", "flock", "make", "tar", "zip", "unzip", "rsync",
    "openssl", "socat", "nmap", "docker", "systemctl", "journalctl", "run-parts",
    "start-stop-daemon", "capsh",
    # 내려받기
    "wget", "curl", "nc",
}


def norm_name(path):
    """python3.6 → python, vim.basic → vim"""
    base = posixpath.basename(path)
    return re.sub(r"\d+$", "", base.split(".")[0])


def who_can_run(mode, group):
    if mode & stat.S_IXOTH:
        return "누구나 실행 가능"
    if mode & stat.S_IXGRP:
        return "그룹 {} 구성원만 실행 가능".format(group)
    return "소유자만 실행 가능"


class Fs02(Check):
    id = "FS-02"
    title = "패키지에 속하지 않거나 비정상 위치의 SUID·SGID 파일"
    severity = "critical"
    attack = "T1548.001"

    def run(self, ctx: Context):
        w = filewalk(ctx)
        self.files_seen, denied, candidates = w.files_seen, w.denied, list(w.suid)
        if denied and os.geteuid() != 0:
            raise Unavailable("디렉터리 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(denied)))

        packages = self.owning_packages(ctx, [c[0] for c in candidates])
        shell_hashes = {}
        for sh in SHELL_BINARIES:
            digest = ctx.sha256(sh)
            if digest:
                shell_hashes.setdefault(digest, sh)
        groups = self.group_names(ctx)
        users = self.user_names(ctx)

        findings, packaged = [], 0
        for path, st in candidates:
            pkg = packages.get(path) if packages is not None else None
            if pkg:
                packaged += 1
            finding = self.judge(ctx, path, st, pkg, packages is not None, shell_hashes, groups, users)
            if finding:
                findings.append(finding)

        self.scope = "파일 {:,}개 중 SUID·SGID {}개 ({})".format(
            self.files_seen, len(candidates),
            "패키지 소속 {}개".format(packaged) if packages is not None else "패키지 정보 없음")
        if denied:
            self.scope += ", root로도 읽지 못한 디렉터리 {}개: {}".format(len(denied), ", ".join(denied[:5]))
        return findings

    @staticmethod
    def owning_packages(ctx, paths):
        """후보 파일 → 소속 패키지. dpkg 정보가 없으면 None. (공통 패키지 DB를 쓴다)"""
        db = packages(ctx)
        if not db.available:
            return None
        found = {}
        for p in paths:
            pkg = db.owner(p)
            if pkg:
                found[p] = pkg
        return found

    @staticmethod
    def group_names(ctx):
        out = {}
        for line in ctx.read_lines("/etc/group", missing_ok=True):
            parts = line.split(":")
            if len(parts) >= 3:
                out.setdefault(parts[2], parts[0])
        return out

    @staticmethod
    def user_names(ctx):
        out = {}
        for line in ctx.read_lines("/etc/passwd", missing_ok=True):
            parts = line.split(":")
            if len(parts) >= 3:
                out.setdefault(parts[2], parts[0])
        return out

    def judge(self, ctx, path, st, pkg, have_dpkg, shell_hashes, groups, users):
        mode = st.st_mode
        suid, sgid = bool(mode & stat.S_ISUID), bool(mode & stat.S_ISGID)
        owner = users.get(str(st.st_uid), str(st.st_uid))
        group = groups.get(str(st.st_gid), str(st.st_gid))
        bits = "/".join(b for b, on in (("SUID({})".format(owner), suid), ("SGID({})".format(group), sgid)) if on)
        critical, warning = [], []

        if path.startswith(USER_AREAS):
            critical.append("사용자가 쓸 수 있는 영역에 있다")
        if any(part.startswith(".") for part in path.split("/") if part):
            critical.append("숨김 경로에 있다")
        digest = ctx.sha256(path)
        if digest and digest in shell_hashes:
            critical.append("셸을 복사한 파일이다 ({}와 내용이 같음)".format(shell_hashes[digest]))
        elif norm_name(path) in SUID_ESCAPE:
            text = "셸 탈출·파일 읽기쓰기가 되는 프로그램이라 실행하는 사람이 {} 권한을 얻을 수 있다".format(
                owner if suid else "그룹 " + group)
            if suid and st.st_uid == 0:
                critical.append(text)
            else:
                warning.append(text)
        if have_dpkg and not pkg:
            warning.append("어떤 패키지에도 속하지 않는다")

        if not critical and not warning:
            return None
        evidence = [
            Evidence(path, "권한 {} {}:{} — {}".format(stat.filemode(mode), owner, group, who_can_run(mode, group))),
            Evidence(path, "패키지: {}".format(pkg or ("없음" if have_dpkg else "확인 불가 (dpkg 정보 없음)"))),
            Evidence(path, "SHA-256: {}".format(digest or "계산 불가")),
            Evidence(path, "내용 변경(mtime): {}".format(timefmt.describe(st.st_mtime, ctx.now)[0])),
            Evidence(path, "속성 변경(ctime, SUID를 붙이면 바뀜): {}".format(timefmt.describe(st.st_ctime, ctx.now)[0])),
        ]
        return self.finding(
            reason="{} 파일 {}: {}".format(bits, path, "; ".join(critical + warning)),
            next_steps="의도된 설정인지 확인하고 아니면 'chmod u-s,g-s'로 제거한다. SUID가 붙은 시점은 ctime으로, "
                       "누가 붙였는지는 auth.log·명령 기록의 chmod로 확인한다. 셸 복사본이면 침입 후 남긴 뒷문으로 본다.",
            evidence=evidence,
            severity="critical" if critical else "warning",
        )
