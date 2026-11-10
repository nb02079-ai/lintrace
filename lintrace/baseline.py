"""기준선 비교 (3단계 2차).

깨끗한 서버를 한 번 찍어 두고(스냅샷) 나중 점검에서 달라진 것만 짚는다. 54개 점검 코드는 건드리지 않고,
기존 수집기(sockets·accounts·packages·filewalk·nfs)를 재사용해 '관찰된 사실'만 모은다.

핵심 원칙 (NET-01 NFS 교훈의 연장): 재부팅·실행마다 바뀌는 값(PID, lockd 동적 포트, 나가는 연결, 시각)은
기준선에 넣지 않는다. 넣으면 아무것도 안 해도 매번 '달라졌다'가 뜬다.

- snapshot(ctx): 사실 사전을 만든다 (저장용). `--save-baseline`
- compare(base, cur): 두 스냅샷을 비교해 [(범위, 종류, 설명, 근거 목록)]을 만든다. `--baseline`
  종류: added(새로 생김·위험) / changed(내용 바뀜·위험) / removed(사라짐·참고)
"""
import hashlib
import os
import stat

from .checks.base import Unavailable
from .checks.persist import md5_file  # noqa: F401  (호환용)
from .collectors.accounts import accounts
from .collectors.filewalk import filewalk
from .collectors.nfs import kernel_nfs
from .collectors.packages import packages
from .collectors.sockets import sockets
from . import __version__, code_sha256

SCHEMA = 1

# ⑥ 해시로 지켜볼 보안 설정 파일 (개별 파일 + 폴더 전체)
CONFIG_FILES = [
    "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/hosts", "/etc/hosts.equiv", "/etc/hosts.allow",
    "/etc/hosts.deny", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/modules", "/etc/profile",
    "/etc/bash.bashrc", "/etc/crontab", "/etc/passwd", "/etc/group", "/etc/shells", "/etc/nsswitch.conf",
    "/etc/login.defs", "/etc/securetty", "/etc/sysctl.conf", "/etc/rc.local", "/etc/pam.conf",
]
CONFIG_DIRS = [
    "/etc/ssh/sshd_config.d", "/etc/sudoers.d", "/etc/pam.d", "/etc/ld.so.conf.d", "/etc/modprobe.d",
    "/etc/modules-load.d", "/etc/profile.d", "/etc/cron.d", "/etc/sysctl.d",
]
# ⑤ 지속성 (자동 실행 표면)
UNIT_DIRS = [
    "/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
    "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/user", "/lib/systemd/user",
    "/usr/lib/systemd/user", "/etc/init.d", "/etc/update-motd.d",
    "/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d", "/run/udev/rules.d",
]
# ③④ SUID·패키지 밖 바이너리를 찾을 시스템 경로
SYSTEM_BIN = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
# 권한을 지켜볼 그룹
PRIV_GROUPS = ("root", "sudo", "wheel", "adm", "docker", "lxd", "disk", "shadow")
AUTH_KEYS = ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2")

CATEGORY_KO = {
    "listen": "리스닝 소켓", "account": "계정", "group": "권한 그룹 구성원", "module": "커널 모듈",
    "package": "설치 패키지", "firewall": "방화벽 규칙", "suid": "SUID·SGID 파일",
    "unpackaged": "시스템 경로의 패키지 밖 파일", "config": "보안 설정 파일", "persistence": "지속성 파일",
}
# 파일 해시로 지켜보는 범주 (added/removed + changed). 나머지는 집합(added/removed)
HASHED = ("suid", "unpackaged", "config", "persistence")


def _sha256_path(ctx, path):
    full = ctx.path(path)
    try:
        st = os.stat(full)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 256 * 1024 * 1024:
            return None
        h = hashlib.sha256()
        with open(full, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _pw_status(field):
    if field in ("", None):
        return "empty"           # 비밀번호 없음 (ACC-04가 위험으로 잡음)
    if field in ("!", "*", "!!", "x") or field.startswith("!") or field.startswith("*"):
        return "locked"
    return "set"                 # 해시값은 저장하지 않는다 — 상태만


def _listen_facts(ctx):
    """리스닝 소켓을 안정된 키 집합으로. 커널 소켓은 동적 포트 대신 커널 서비스 이름으로 가린다."""
    out = set()
    try:
        table = sockets(ctx)
    except Unavailable:
        return out
    nfs = kernel_nfs(ctx)
    for s in table.socks:
        if not s.listening and not s.proto.startswith(("raw", "packet")):
            continue
        fam = s.proto.rstrip("6")  # tcp6→tcp, udp6→udp (듀얼스택이 뒤집히지 않게)
        if s.kernel:
            who = nfs.owner(s) if nfs.active else None
            # 커널 소켓은 포트가 동적일 수 있어 포트를 키에서 뺀다
            out.add("{}|커널:{}".format(fam, who or "kernel"))
            continue
        port = s.local[1] if s.local else "?"
        owner = "?"
        if s.owners:
            p = s.owners[0][0]
            owner = ctx.realpath(p.exe_path) if p.exe_path else p.name
        out.add("{}|{}|{}".format(fam, port, owner))
    return out


def _account_facts(ctx):
    acc = accounts(ctx)
    try:
        shadow = acc.shadow()
    except Unavailable:
        shadow = {}
    users = set()
    for u in acc.users:
        pw = _pw_status(shadow.get(u.name, (u.password, 0))[0] if shadow else u.password)
        users.add("{}|uid={}|gid={}|shell={}|home={}|pw={}".format(u.name, u.uid, u.gid, u.shell, u.home, pw))
    priv = set()
    for g in acc.groups:
        if g.name in PRIV_GROUPS:
            for m in acc.members(g):
                priv.add("{}|{}".format(g.name, m))
    return users, priv


def _hashed_files(ctx, paths):
    out = {}
    for p in paths:
        digest = _sha256_path(ctx, p)
        if digest is not None:
            out[p] = digest
    return out


def _dir_files(ctx, dirs):
    paths = []
    for d in dirs:
        try:
            names = ctx.list_dir(d)
        except Unavailable:
            continue
        for n in names:
            paths.append(d.rstrip("/") + "/" + n)
    return paths


def snapshot(ctx, with_packages=True):
    """현재 상태의 사실 사전. 저장용."""
    users, priv = _account_facts(ctx)

    # ③ SUID, ④ 패키지 밖 바이너리
    suid, unpackaged = {}, {}
    try:
        w = filewalk(ctx)
        for path, st in w.suid:
            d = _sha256_path(ctx, path)
            if d:
                suid[path] = d
    except Unavailable:
        pass
    db = packages(ctx)
    if db.available:
        for d in SYSTEM_BIN:
            try:
                names = ctx.list_dir(d)
            except Unavailable:
                continue
            for n in names:
                path = d.rstrip("/") + "/" + n
                st = ctx.stat(path)
                if st is None or stat.S_ISDIR(st.st_mode):
                    continue
                real = ctx.realpath(path)
                if db.owner(path) or db.owner(real) or db.diversion(path) or db.diversion(real):
                    continue
                dig = _sha256_path(ctx, path)
                if dig:
                    unpackaged[path] = dig

    # ⑤ 지속성 파일
    persistence = _hashed_files(ctx, _dir_files(ctx, UNIT_DIRS))
    for p in ["/etc/rc.local"]:
        d = _sha256_path(ctx, p)
        if d:
            persistence.setdefault(p, d)

    # ⑥ 보안 설정 파일
    config_paths = list(CONFIG_FILES) + _dir_files(ctx, CONFIG_DIRS) + list(AUTH_KEYS)
    for _, home in _homes(ctx):
        config_paths.append(home.rstrip("/") + "/.ssh/authorized_keys")
    config = _hashed_files(ctx, config_paths)

    # ⑦ 방화벽 — nft·iptables-save 조회가 nf_tables 모듈을 자동으로 올리므로 모듈 목록보다 먼저 한다
    firewall = _firewall_hash(ctx)

    # 커널 모듈 — 방화벽 조회 뒤에 읽는다 (안 그러면 nft가 올린 nf_tables가 다음 실행 때 '새로 생김'으로 뜬다)
    modules = set()
    for line in ctx.read_lines("/proc/modules", missing_ok=True):
        f = line.split()
        if f:
            modules.add(f[0])

    # ⑧ 패키지 목록 (옵션)
    pkgs = _package_list(ctx) if with_packages else None

    facts = {
        "listen": sorted(_listen_facts(ctx)),
        "account": sorted(users),
        "group": sorted(priv),
        "module": sorted(modules),
        "firewall": firewall,
        "suid": suid,
        "unpackaged": unpackaged,
        "config": config,
        "persistence": persistence,
    }
    if pkgs is not None:
        facts["package"] = sorted(pkgs)
    return {
        "schema": SCHEMA,
        "tool": {"name": "lintrace", "version": __version__, "code_sha256": code_sha256()},
        "created": _now_iso(),
        "host": _host(ctx),
        "kernel": os.uname().release if ctx.root == "/" else None,
        "os": _os_name(ctx),
        "root": ctx.root,
        "facts": facts,
    }


def _homes(ctx):
    from .checks.persist import homes
    return homes(ctx)


def _now_iso():
    import datetime
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _host(ctx):
    lines = ctx.read_lines("/etc/hostname", missing_ok=True)
    host = lines[0].strip() if lines else None
    if ctx.root == "/":
        import socket
        host = socket.gethostname() or host
    return host


def _os_name(ctx):
    for line in ctx.read_lines("/etc/os-release", missing_ok=True):
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _firewall_hash(ctx):
    """방화벽 규칙을 정규화해 sha256. 카운터([n:n])·주석은 뺀다 (매번 바뀌므로)."""
    from .checks.net_05 import RULE_FILES, run_cmd
    import re
    parts = []
    if ctx.root == "/":
        for args in (["iptables-save"], ["ip6tables-save"], ["nft", "list", "ruleset"]):
            text = run_cmd(args)
            if text:
                parts.append(text)
    for path in RULE_FILES:
        lines = ctx.read_lines(path, missing_ok=True)
        if lines:
            parts.append("\n".join(lines))
    if not parts:
        return None
    blob = "\n".join(parts)
    norm = []
    for line in blob.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = re.sub(r"\[\d+:\d+\]", "", s)   # iptables 카운터
        norm.append(s.strip())
    return hashlib.sha256("\n".join(norm).encode("utf-8", "replace")).hexdigest()


def _package_list(ctx):
    """설치된 패키지 이름|버전 집합 (dpkg status). dpkg가 없으면 빈 집합."""
    out = set()
    pkg = ver = None
    installed = False
    for line in ctx.read_lines("/var/lib/dpkg/status", missing_ok=True):
        if line.startswith("Package:"):
            pkg, ver, installed = line.split(":", 1)[1].strip(), None, False
        elif line.startswith("Status:"):
            installed = "install ok installed" in line
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        elif not line.strip():
            if pkg and installed:
                out.add("{}|{}".format(pkg, ver or "?"))
            pkg = ver = None
            installed = False
    if pkg and installed:
        out.add("{}|{}".format(pkg, ver or "?"))
    return out


def mismatch(base, ctx):
    """기준선과 현재 머신이 다른지 (호스트·커널·OS). 다르면 설명 문자열, 같으면 None."""
    cur_host, cur_kernel, cur_os = _host(ctx), (os.uname().release if ctx.root == "/" else None), _os_name(ctx)
    diffs = []
    if base.get("host") and cur_host and base["host"] != cur_host:
        diffs.append("호스트 {} ≠ {}".format(base["host"], cur_host))
    if base.get("kernel") and cur_kernel and base["kernel"] != cur_kernel:
        diffs.append("커널 {} ≠ {}".format(base["kernel"], cur_kernel))
    if base.get("os") and cur_os and base["os"] != cur_os:
        diffs.append("OS {} ≠ {}".format(base["os"], cur_os))
    return ", ".join(diffs) if diffs else None


class Change:
    __slots__ = ("category", "kind", "key", "detail")

    def __init__(self, category, kind, key, detail):
        self.category = category        # listen / account / ...
        self.kind = kind                # added / removed / changed
        self.key = key
        self.detail = detail            # 사람이 읽을 설명

    def to_dict(self):
        return {"category": self.category, "kind": self.kind, "key": self.key, "detail": self.detail}


def compare(base, cur):
    """두 스냅샷의 facts를 비교. [Change] (범주 순 → added·changed·removed 순)."""
    bf, cf = base.get("facts", {}), cur.get("facts", {})
    order = ["listen", "account", "group", "module", "package", "firewall", "suid", "unpackaged",
             "config", "persistence"]
    kind_order = {"added": 0, "changed": 1, "removed": 2}
    changes = []
    for cat in order:
        b, c = bf.get(cat), cf.get(cat)
        if b is None and c is None:
            continue
        if cat == "firewall":
            if b != c and not (b is None or c is None):
                changes.append(Change(cat, "changed", "ruleset", "방화벽 규칙 해시가 달라졌다"))
            continue
        if cat in HASHED:
            b, c = b or {}, c or {}
            for path in sorted(set(c) - set(b)):
                changes.append(Change(cat, "added", path, "새로 생김: {}".format(path)))
            for path in sorted(set(b) - set(c)):
                changes.append(Change(cat, "removed", path, "사라짐: {}".format(path)))
            for path in sorted(set(b) & set(c)):
                if b[path] != c[path]:
                    changes.append(Change(cat, "changed", path, "내용 바뀜: {}".format(path)))
        else:
            b, c = set(b or []), set(c or [])
            for key in sorted(c - b):
                changes.append(Change(cat, "added", key, "새로 생김: {}".format(key)))
            for key in sorted(b - c):
                changes.append(Change(cat, "removed", key, "사라짐: {}".format(key)))
    changes.sort(key=lambda ch: (order.index(ch.category), kind_order[ch.kind], ch.key))
    return changes


KIND_SEVERITY = {"added": "warning", "changed": "warning", "removed": "info"}
KIND_KO = {"added": "새로 생김", "changed": "내용 바뀜", "removed": "사라짐"}


def report_block(base, changes, mism):
    """리포트에 실을 기준선 비교 사전."""
    counts = {"added": 0, "changed": 0, "removed": 0}
    items = []
    for ch in changes:
        counts[ch.kind] += 1
        d = ch.to_dict()
        d["severity"] = KIND_SEVERITY[ch.kind]
        d["category_ko"] = CATEGORY_KO.get(ch.category, ch.category)
        d["kind_ko"] = KIND_KO[ch.kind]
        items.append(d)
    return {
        "source": {"created": base.get("created"), "host": base.get("host"), "kernel": base.get("kernel"),
                   "os": base.get("os"), "code_sha256": (base.get("tool") or {}).get("code_sha256")},
        "mismatch": mism,
        "counts": counts,
        "changes": items,
    }


def bumps_verdict(block):
    """기준선 변화가 전체 판정을 위험으로 올려야 하는지 (새로 생김·바뀜이 있으면)."""
    c = block.get("counts", {})
    return (c.get("added", 0) + c.get("changed", 0)) > 0
