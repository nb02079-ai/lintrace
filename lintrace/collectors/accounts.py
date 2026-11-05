"""계정 수집기: /etc/passwd, /etc/shadow, /etc/group을 한 번만 읽는다 (ACC-02·03·04·05).

shadow는 root만 읽을 수 있다. 못 읽으면 shadow()가 Unavailable을 낸다.
"""
SYSTEM_UID_MAX = 999
NOBODY_UID = 65534


class Account:
    __slots__ = ("name", "password", "uid", "gid", "home", "shell", "lineno", "line")

    def __init__(self, parts, lineno, line):
        self.name, self.password = parts[0], parts[1]
        self.uid = int(parts[2]) if parts[2].isdigit() else -1
        self.gid = int(parts[3]) if parts[3].isdigit() else -1
        self.home, self.shell = parts[5], parts[6]
        self.lineno, self.line = lineno, line

    @property
    def is_system(self):
        return 1 <= self.uid <= SYSTEM_UID_MAX or self.uid == NOBODY_UID


class Group:
    __slots__ = ("name", "gid", "members", "lineno", "line")

    def __init__(self, parts, lineno, line):
        self.name = parts[0]
        self.gid = int(parts[2]) if parts[2].isdigit() else -1
        self.members = [m for m in parts[3].split(",") if m] if len(parts) > 3 else []
        self.lineno, self.line = lineno, line


class Accounts:
    def __init__(self, ctx):
        self.ctx = ctx
        self.users = []
        for no, line in enumerate(ctx.read_lines("/etc/passwd"), start=1):
            parts = line.split(":")
            if len(parts) >= 7 and not line.startswith("#"):
                self.users.append(Account(parts, no, line))
        self.groups = []
        for no, line in enumerate(ctx.read_lines("/etc/group", missing_ok=True), start=1):
            parts = line.split(":")
            if len(parts) >= 3 and not line.startswith("#"):
                self.groups.append(Group(parts, no, line))
        self._shadow = None
        self.has_shadow = ctx.stat("/etc/shadow", follow=True) is not None
        self.has_group = ctx.stat("/etc/group", follow=True) is not None

    def shadow(self):
        """이름 → (비밀번호 칸, 줄 번호). 파일이 없으면 빈 dict, 못 읽으면 Unavailable."""
        if self._shadow is None:
            lines = self.ctx.read_lines("/etc/shadow", missing_ok=True)  # 못 읽으면 여기서 Unavailable
            shadow = {}  # 다 읽은 뒤에만 저장한다 — 실패를 저장하면 다음 항목이 빈 shadow를 '정상'으로 본다
            for no, line in enumerate(lines, start=1):
                parts = line.split(":")
                if len(parts) >= 2 and not line.startswith("#"):
                    shadow.setdefault(parts[0], (parts[1], no))
            self._shadow = shadow
        return self._shadow

    def group_by_name(self, name):
        for g in self.groups:
            if g.name == name:
                return g
        return None

    def members(self, group):
        """보조 구성원 + 기본 그룹이 이 그룹인 계정."""
        names = list(group.members)
        for u in self.users:
            if u.gid == group.gid and u.name not in names:
                names.append(u.name)
        return names


def accounts(ctx):
    cached = getattr(ctx, "_accounts", None)
    if cached is None:
        cached = Accounts(ctx)
        ctx._accounts = cached
    return cached
