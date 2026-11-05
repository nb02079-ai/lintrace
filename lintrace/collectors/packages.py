"""패키지 DB 수집기 (dpkg).

/var/lib/dpkg/info/*.list(파일 소속)와 *.md5sums(설치 당시 해시)를 한 번만 읽어 여러 항목이 함께 쓴다.
usrmerge 시스템에서는 dpkg가 /lib/x/y로 적은 파일이 실제로는 /usr/lib/x/y이고, 반대도 있으므로
두 경로를 모두 맞춰 본다.

사용법: db = packages(ctx) — 같은 Context에서는 저장된 것을 돌려준다.
"""
import posixpath

INFO = "/var/lib/dpkg/info"
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
