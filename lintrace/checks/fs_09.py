"""FS-09 immutable 속성 설정·실행 파일.

'chattr +i'(immutable)를 붙인 파일은 root도 지우거나 고칠 수 없다 (먼저 'chattr -i'를 해야 함). 공격자는
authorized_keys·crontab·백도어 실행 파일에 붙여 관리자의 정리를 막는다. '+a'(append-only)는 덧붙이기만 된다.

읽는 곳 (2026-11-06 결정 4 — 파일마다 열어야 하므로 핵심 위치만): /etc, /bin·/sbin·/usr/bin·/usr/sbin,
/lib/systemd·/usr/lib/systemd, /root, 홈의 .ssh·셸 초기화 파일, /var/spool/cron, 웹 루트, 임시 폴더
판정
- 위험: 위 위치의 파일·폴더에 immutable·append-only
- 심각: authorized_keys·passwd·shadow·group·sudoers·crontab·ld.so.preload·systemd 유닛·셸 초기화 파일,
  임시 폴더의 실행 파일
"""
import fcntl
import os
import posixpath
import stat
import struct

from .base import Check, Context, Evidence, Unavailable
from .fs_06 import Fs06
from .persist import Item, group, homes, uid_name

FS_IOC_GETFLAGS = 0x80086601
IMMUTABLE, APPEND = 0x10, 0x20
RECURSIVE = ["/etc", "/root", "/var/spool/cron", "/var/spool/cron/crontabs", "/lib/systemd/system",
             "/usr/lib/systemd/system", "/tmp", "/var/tmp", "/dev/shm"]
TOP_ONLY = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
HOME_ITEMS = [".ssh", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".bashrc", ".profile", ".bash_profile",
              ".bash_login", ".zshrc"]
CRITICAL_NAMES = {"authorized_keys", "authorized_keys2", "passwd", "shadow", "group", "gshadow", "sudoers",
                  "crontab", "ld.so.preload", ".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc"}
CRITICAL_DIRS = ("/etc/sudoers.d/", "/etc/cron.", "/var/spool/cron/", "/etc/systemd/system/", "/lib/systemd/system/",
                 "/usr/lib/systemd/system/", "/etc/profile.d/")
TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/")
MAX_FILES = 100000


class Fs09(Check):
    id = "FS-09"
    title = "immutable 속성 설정·실행 파일"
    severity = "warning"
    attack = "T1222.002"

    def flags(self, ctx, path):
        """파일 속성 플래그. 읽을 수 없거나 지원하지 않으면 None."""
        try:
            fd = os.open(ctx.path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_NOCTTY)
        except PermissionError:
            self.denied += 1
            return None
        except OSError:
            return None
        try:
            return struct.unpack("i", fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("i", 0)))[0]
        except OSError:
            self.unsupported += 1
            return None
        finally:
            os.close(fd)

    def targets(self, ctx):
        seen = set()
        for d in TOP_ONLY:
            if ctx.realpath(d) in seen:
                continue
            seen.add(ctx.realpath(d))
            yield d
            for n in sorted(ctx.list_dir(d)):
                yield posixpath.join(d, n)
        roots = list(RECURSIVE) + Fs06().web_roots(ctx)
        for _, home in homes(ctx):
            if home == "/root":
                continue
            for n in HOME_ITEMS:
                yield posixpath.join(home, n)
        for root in roots:
            if ctx.realpath(root) in seen or ctx.stat(root, follow=True) is None:
                continue
            seen.add(ctx.realpath(root))
            stack = [root]
            while stack:
                d = stack.pop()
                yield d
                try:
                    entries = sorted(os.scandir(ctx.path(d)), key=lambda e: e.name)
                except OSError:
                    continue
                for e in entries:
                    child = posixpath.join(d, e.name)
                    if e.is_dir(follow_symlinks=False):
                        stack.append(child)
                    else:
                        yield child

    def run(self, ctx: Context):
        self.denied = self.unsupported = 0
        checked, items = 0, []
        for path in self.targets(ctx):
            if checked >= MAX_FILES:
                break
            st = ctx.stat(path)
            if st is None or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                continue
            checked += 1
            fl = self.flags(ctx, path)
            if not fl or not fl & (IMMUTABLE | APPEND):
                continue
            what = "immutable(+i — root도 고치거나 지울 수 없음)" if fl & IMMUTABLE else "append-only(+a — 덧붙이기만 됨)"
            cond = [("warning", "{}에 {} 속성이 붙어 있다".format("폴더" if stat.S_ISDIR(st.st_mode) else "파일", what))]
            name = posixpath.basename(path)
            if name in CRITICAL_NAMES or path.startswith(CRITICAL_DIRS):
                cond.append(("critical", "계정·인증·예약 작업·자동 실행 파일이라 공격자가 고친 내용을 지키려는 것일 수 있다"))
            if path.startswith(TEMP) and stat.S_ISREG(st.st_mode) and st.st_mode & 0o111:
                cond.append(("critical", "임시 폴더의 실행 파일이 지워지지 않게 막혀 있다"))
            items.append(Item(path, cond, [Evidence(path, "속성 플래그 0x{:x}, 소유자 {}, 권한 {:o}".format(
                fl, uid_name(ctx, st.st_uid), stat.S_IMODE(st.st_mode)))]))
        if self.denied and os.geteuid() != 0:
            raise Unavailable("파일 {}개를 열 권한 없음 (root로 실행 필요)".format(self.denied))
        findings = group(self, items, "내용을 확인한 뒤 'chattr -i 파일'(append-only는 -a)로 풀고 정리한다. 누가 붙였는지는 명령 기록의 "
                                      "chattr와 ctime으로 본다. 속성을 붙인 도구가 남아 있는지(CMD-01) 확인한다.", "파일")
        self.scope = "핵심 위치 파일·폴더 {:,}개{}".format(
            checked, " (속성을 지원하지 않는 파일시스템 {}개)".format(self.unsupported) if self.unsupported else "")
        return findings
