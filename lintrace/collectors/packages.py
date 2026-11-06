"""패키지 DB 수집기 (dpkg).

/var/lib/dpkg/info/*.list(파일 소속)와 *.md5sums(설치 당시 해시)를 한 번만 읽어 여러 항목이 함께 쓴다.
usrmerge 시스템에서는 dpkg가 /lib/x/y로 적은 파일이 실제로는 /usr/lib/x/y이고, 반대도 있으므로
두 경로를 모두 맞춰 본다.

설정 파일(conffile)은 md5sums에 없고 /var/lib/dpkg/status의 'Conffiles:'에 설치 당시 md5가 있다.
dpkg diversion(/var/lib/dpkg/diversions — 다른 패키지와 겹치는 파일을 옮겨 둔 것, 예: /bin/sh → /bin/sh.distrib)은
3줄씩 (원래 경로, 옮긴 경로, 옮긴 패키지)이다.

사용법: db = packages(ctx) — 같은 Context에서는 저장된 것을 돌려준다.
"""
import posixpath
import re

INFO = "/var/lib/dpkg/info"
STATUS = "/var/lib/dpkg/status"
DIVERSIONS = "/var/lib/dpkg/diversions"
MD5 = re.compile(r"^[0-9a-f]{32}$")
USRMERGE = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")


def path_aliases(path):
    """usrmerge 시스템에서 dpkg 목록이 /bin/su로 적었어도 /usr/bin/su와 맞도록 별칭을 만든다."""
    out = {path}
    for top in USRMERGE:
        if path.startswith("/usr" + top + "/"):
            out.add(path[4:])
        elif path.startswith(top + "/"):
            out.add("/usr" + path)
    return out


class PackageDB:
    def __init__(self, ctx):
        self.ctx = ctx
        self.available = ctx.stat(INFO, follow=True) is not None
        self._owner = None
        self._md5 = None
        self._conf = None
        self._div = None

    def _load_owner(self):
        owner = {}  # 다 읽은 뒤에만 저장 (중간에 Unavailable이 나면 다음에 다시 시도)
        for name in self.ctx.list_dir(INFO):
            if name.endswith(".list"):
                pkg = name[:-5].split(":")[0]
                for line in self.ctx.read_lines(posixpath.join(INFO, name), missing_ok=True):
                    owner.setdefault(line.strip(), pkg)
        self._owner = owner

    def _load_md5(self):
        md5 = {}
        for name in self.ctx.list_dir(INFO):
            if name.endswith(".md5sums"):
                pkg = name[:-8].split(":")[0]
                for line in self.ctx.read_lines(posixpath.join(INFO, name), missing_ok=True):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        md5.setdefault("/" + parts[1].strip().lstrip("/"), (parts[0].lower(), pkg))
        self._md5 = md5

    def _load_conf(self):
        conf, pkg, in_conf = {}, None, False
        for line in self.ctx.read_lines(STATUS, missing_ok=True):
            if line.startswith("Package:"):
                pkg, in_conf = line.split(":", 1)[1].strip(), False
            elif line.startswith("Conffiles:"):
                in_conf = True
            elif in_conf and line.startswith(" "):
                parts = line.split()
                # ' /etc/x md5 [obsolete|remove-on-upgrade]' — 더 이상 쓰지 않는 항목은 뺀다
                if len(parts) >= 2 and parts[0].startswith("/") and MD5.match(parts[1].lower()) \
                        and "obsolete" not in parts[2:] \
                        and "remove-on-upgrade" not in parts[2:] and pkg:
                    conf.setdefault(parts[0], (parts[1].lower(), pkg))
            else:
                in_conf = False
        self._conf = conf

    def _load_div(self):
        lines = self.ctx.read_lines(DIVERSIONS, missing_ok=True)
        div = {}
        for i in range(0, len(lines) - 2, 3):
            div[lines[i + 1].strip()] = (lines[i].strip(), lines[i + 2].strip())
        self._div = div

    def conffile(self, path):
        """설정 파일이면 (설치 당시 md5, 패키지). 아니면 None."""
        if not self.available:
            return None
        if self._conf is None:
            self._load_conf()
        for alias in sorted(path_aliases(path)):
            if alias in self._conf:
                return self._conf[alias]
        return None

    def conffiles(self):
        if not self.available:
            return {}
        if self._conf is None:
            self._load_conf()
        return self._conf

    def diversion(self, path):
        """dpkg diversion으로 옮겨 둔 파일이면 (원래 경로, 옮긴 패키지). 아니면 None."""
        if not self.available:
            return None
        if self._div is None:
            self._load_div()
        for alias in sorted(path_aliases(path)):
            if alias in self._div:
                return self._div[alias]
        return None

    def diverted_paths(self):
        """diversion에 관련된 모든 경로 (원래·옮긴 곳, usrmerge 별칭 포함)."""
        if self._div is None:
            if not self.available:
                return set()
            self._load_div()
        out = set()
        for to, (frm, _) in self._div.items():
            out |= path_aliases(to) | path_aliases(frm)
        return out

    def md5_entries(self):
        """md5sums 전체 {경로: (md5, 패키지)} (FS-04)."""
        if not self.available:
            return {}
        if self._md5 is None:
            self._load_md5()
        return self._md5

    def owner(self, path):
        """파일을 설치한 패키지 이름. 없거나 dpkg 정보가 없으면 None."""
        if not self.available:
            return None
        if self._owner is None:
            self._load_owner()
        for alias in sorted(path_aliases(path)):
            if alias in self._owner:
                return self._owner[alias]
        return None

    def md5(self, path):
        """설치 당시 MD5와 패키지 (dpkg md5sums). 기록이 없으면 None."""
        if not self.available:
            return None
        if self._md5 is None:
            self._load_md5()
        for alias in sorted(path_aliases(path)):
            if alias in self._md5:
                return self._md5[alias]
        return None


def packages(ctx):
    db = getattr(ctx, "_package_db", None)
    if db is None:
        db = PackageDB(ctx)
        ctx._package_db = db
    return db
