"""파일시스템 전체 훑기 (FS-02·03·08이 함께 쓴다).

한 번 훑으면서 SUID·SGID 파일(FS-02), capability가 붙은 파일(FS-03, security.capability 확장 속성),
숨김 이름의 폴더(FS-08)를 모은다. 같은 디스크를 여러 번 훑지 않으려고 Context에 저장한다.

범위: 파일시스템 전체. /proc, /sys, /run, /dev(/dev/shm은 포함), /snap, 네트워크·가상 파일시스템은 뺀다.
링크는 따라가지 않는다.

사용법: w = filewalk(ctx) — 같은 Context에서는 저장된 결과를 돌려준다.
"""
import os
import posixpath
import re
import stat

STATIC_EXCLUDE = ("/proc", "/sys", "/run", "/dev", "/snap")
EXTRA_ROOTS = ("/dev/shm",)  # /dev를 빼도 공격자가 자주 쓰는 /dev/shm은 본다
SKIP_FSTYPES = {
    # 네트워크
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "sshfs", "9p", "ceph", "glusterfs",
    "fuse.glusterfs", "davfs", "fuse.davfs2", "afs", "lustre",
    # 가상
    "proc", "sysfs", "cgroup", "cgroup2", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
    "autofs", "mqueue", "hugetlbfs", "configfs", "fusectl", "binfmt_misc", "devpts", "efivarfs",
    "devtmpfs", "rpc_pipefs", "nsfs", "selinuxfs",
}
CAP_XATTR = "security.capability"


def unescape_mount(s):
    """/proc/mounts의 '\\040' 같은 8진수 표기를 푼다."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


class Walk:
    def __init__(self):
        self.files_seen = 0
        self.suid = []      # [(경로, stat)]
        self.caps = []      # [(경로, stat, 속성 바이트)]
        self.hidden = []    # [(경로, stat)] — 이름이 '.'으로 시작하는 폴더
        self.future = []    # [(경로, stat)] — 변경 시각이 미래인 파일 (LOG-06)
        self.denied = []    # 읽지 못한 폴더


def read_cap(full):
    try:
        return os.getxattr(full, CAP_XATTR, follow_symlinks=False)
    except (OSError, AttributeError):
        return None  # 속성 없음(ENODATA)·지원 안 함


def _walk(ctx, start, excluded, w, future_after):
    stack = [start]
    while stack:
        logical = stack.pop()
        try:
            entries = list(os.scandir(ctx.path(logical)))
        except PermissionError:
            w.denied.append(logical)
            continue
        except (FileNotFoundError, NotADirectoryError):
            continue  # 그사이 사라짐
        for entry in entries:
            child = posixpath.join(logical, entry.name)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                if child in excluded:
                    continue
                if entry.name.startswith("."):
                    w.hidden.append((child, st))
                stack.append(child)
            elif stat.S_ISREG(st.st_mode):
                w.files_seen += 1
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    w.suid.append((child, st))
                if future_after and st.st_mtime > future_after:
                    w.future.append((child, st))
                cap = read_cap(entry.path)
                if cap:
                    w.caps.append((child, st, cap))


def filewalk(ctx):
    cached = getattr(ctx, "_filewalk", None)
    if cached is not None:
        return cached
    excluded = set(STATIC_EXCLUDE)
    for line in ctx.read_lines("/proc/mounts", missing_ok=True):
        parts = line.split()
        if len(parts) >= 3 and parts[2] in SKIP_FSTYPES:
            excluded.add(unescape_mount(parts[1]))
    excluded.discard("/")
    w = Walk()
    future_after = ctx.now + 86400     # 지금보다 하루 넘게 미래
    roots = ["/"] + [r for r in EXTRA_ROOTS if ctx.stat(r, follow=True) is not None]
    for start in roots:
        _walk(ctx, start, excluded if start == "/" else set(), w, future_after)
    for lst in (w.suid, w.caps, w.hidden, w.future):
        lst.sort(key=lambda x: x[0])  # 디렉터리를 읽는 순서와 관계없이 같은 결과
    ctx._filewalk = w
    return w


def require_root(w, what="디렉터리"):
    """root가 아닌데 못 읽은 곳이 있으면 결과를 믿을 수 없다 — 호출한 항목이 Unavailable을 낸다."""
    return bool(w.denied) and os.geteuid() != 0
