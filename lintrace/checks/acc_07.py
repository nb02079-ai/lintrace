"""ACC-07 authorized_keys 의심 키와 변경 이력.

모든 계정의 SSH 공개키 파일을 찾아, 키가 있어서는 안 되는 곳에 있는 키와
키를 몰래 심을 수 있는 권한 설정을 찾는다.

시간 원칙에 따라 파일 변경 시각은 위험도에 쓰지 않고 근거에 경과 시간으로만 보인다.
'새로 생긴 키' 판정은 3단계 기준선 비교가 맡는다.

판정
- 심각: root 외 UID 0 계정에 키가 있음
- 심각: 시스템 계정(UID 1~999, nobody)에 키가 있음
        (모든 키에 command= 강제 명령이 걸려 있으면 위험으로 낮춤 — git 서버 등의 정상 사용)
- 위험: 키 파일이나 .ssh를 다른 사용자가 쓸 수 있음 / 키 파일 소유자가 다른 계정
- 위험: 키 파일 변경 시각이 현재보다 미래 (조작 흔적)
- 위험: sshd가 기본 위치가 아닌 곳에서 키를 읽도록 설정됨 (AuthorizedKeysFile)
- 참고: 그 외 계정(root, 일반 사용자)에 등록된 키 / 같은 키가 여러 계정에 등록됨

알려진 한계
- AuthorizedKeysCommand(외부 프로그램이 키를 주는 방식)는 다루지 않는다.
- Match 블록 안의 AuthorizedKeysFile도 조건 없이 모두 점검 대상에 넣는다.
"""
import base64
import binascii
import fnmatch
import hashlib
import posixpath
import re
import stat

from .. import timefmt
from .base import Check, Context, Evidence

DEFAULT_KEY_FILES = [".ssh/authorized_keys", ".ssh/authorized_keys2"]
SSHD_CONFIG = "/etc/ssh/sshd_config"
KEY_LINE = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[A-Za-z0-9@.\-]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$")
CONFIG_LINE = re.compile(r"^([A-Za-z]+)(?:\s*=\s*|\s+)(.*)$")
MAX_DEPTH = 8
SYSTEM_UID_MAX = 999
NOBODY_UID = 65534


def fingerprint(blob_b64):
    """ssh-keygen -lf 와 같은 SHA256 지문. 해석할 수 없으면 None."""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_keys(lines):
    """authorized_keys의 키 줄을 해석한다. [(줄 번호, 종류, 지문, 주석, 옵션)]"""
    keys = []
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = KEY_LINE.search(s)
        if not m:
            keys.append((no, "?", None, "", "해석할 수 없는 줄"))
            continue
        options = s[:m.start()].strip()
        keys.append((no, m.group(1), fingerprint(m.group(2)), (m.group(3) or "").strip(), options))
    return keys


def expand_pattern(pattern, user, uid, home):
    """AuthorizedKeysFile 값의 %h, %u, %U, %% 를 풀고 상대 경로는 홈 기준으로 바꾼다."""
    out = (pattern.replace("%%", "\0").replace("%h", home).replace("%u", user)
           .replace("%U", str(uid)).replace("\0", "%"))
    if not out.startswith("/"):
        if not home:
            return None
        out = posixpath.join(home, out)
    return posixpath.normpath(out)


def is_standard(pattern):
    p = pattern[3:] if pattern.startswith("%h/") else pattern
    return p in DEFAULT_KEY_FILES or pattern == "none"


class _SshdConfig:
    """sshd_config와 Include된 파일을 읽는다 (ACC-07 AuthorizedKeysFile, ACC-10 위험 설정)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.entries = []      # AuthorizedKeysFile: (파일, 줄 번호, 줄, [값들])
        self.directives = []   # 모든 지시어: (파일, 줄 번호, 줄, 소문자 키, 값, Match 블록 안인지)
        self.visited = set()

    def parse(self, path, depth=0):
        if depth > MAX_DEPTH or path in self.visited:
            return
        self.visited.add(path)
        in_match = False
        for no, raw in enumerate(self.ctx.read_lines(path, missing_ok=True), start=1):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            m = CONFIG_LINE.match(s)
            if not m:
                continue
            key, value = m.group(1).lower(), m.group(2).strip()
            if key == "match":
                in_match = value.lower() != "all"
            self.directives.append((path, no, s, key, value, in_match))
            if key == "include":
                for target in value.split():
                    if not target.startswith("/"):
                        target = posixpath.join("/etc/ssh", target)
                    self.include(target, depth)
            elif key == "authorizedkeysfile":
                self.entries.append((path, no, s, value.split()))

    def include(self, target, depth):
        directory, pattern = posixpath.split(target)
        if any(c in pattern for c in "*?["):
            for name in self.ctx.list_dir(directory):
                if fnmatch.fnmatch(name, pattern):
                    self.parse(posixpath.join(directory, name), depth + 1)
        else:
            self.parse(target, depth + 1)

    def patterns(self):
        out = list(DEFAULT_KEY_FILES)
        for _, _, _, values in self.entries:
            for v in values:
                if v != "none" and v not in out:
                    out.append(v)
        return out


def account_kind(name, uid):
    if uid == 0:
        return "root" if name == "root" else "uid0"
    if 1 <= uid <= SYSTEM_UID_MAX or uid == NOBODY_UID:
        return "system"
    return "user"


class Acc07(Check):
    id = "ACC-07"
    title = "authorized_keys 의심 키와 변경 이력"
    severity = "critical"
    attack = "T1098.004"

    def run(self, ctx: Context):
        findings = []

        config = _SshdConfig(ctx)
        config.parse(SSHD_CONFIG)
        odd = [(p, n, s) for p, n, s, values in config.entries if not all(is_standard(v) for v in values)]
        if odd:
            findings.append(self.finding(
                reason="sshd가 기본 위치가 아닌 곳에서도 키를 읽도록 설정되어 있다. 키를 눈에 띄지 않는 곳에 숨기는 데 쓰일 수 있다.",
                next_steps="이 설정이 의도된 것인지 확인하고, 설정된 경로의 키 파일 내용과 설정 파일 변경 시각을 확인한다.",
                evidence=[Evidence(p, "{}행: {}".format(n, s)) for p, n, s in odd],
                severity="warning",
            ))

        # 키 파일 경로 → 그 파일을 쓰는 계정들 (홈을 공유하는 계정은 한 파일에 묶인다)
        owners = {}
        for line in ctx.read_lines("/etc/passwd"):
            parts = line.split(":")
            if len(parts) < 7 or line.startswith("#") or not parts[2].isdigit():
                continue
            name, uid, home = parts[0], int(parts[2]), parts[5]
            for pattern in config.patterns():
                path = expand_pattern(pattern, name, uid, home)
                if path:
                    owners.setdefault(path, []).append((name, uid))

        seen_keys = {}  # 지문 → [(파일, 계정 이름들)]
        self.key_files = self.key_count = 0
        for path in sorted(owners):
            st = ctx.stat(path)
            if st is None or stat.S_ISDIR(st.st_mode):
                continue
            accounts = owners[path]
            finding = self.check_file(ctx, path, st, accounts, seen_keys)
            if finding:
                findings.append(finding)
        self.scope = "키 파일 {}개, 키 {}개".format(self.key_files, self.key_count)

        dup = {fp: places for fp, places in seen_keys.items() if len(places) > 1}
        for fp in sorted(dup):
            findings.append(self.finding(
                reason="같은 키({})가 여러 계정에 등록되어 있다: {}".format(
                    fp, ", ".join("{}({})".format("·".join(names), p) for p, names in dup[fp])),
                next_steps="한 사람의 키가 여러 계정에 들어간 이유를 확인한다. 공격자가 하나의 키를 여러 계정에 심는 경우가 있다.",
                evidence=[Evidence(p, "지문 {}".format(fp)) for p, _ in dup[fp]],
                severity="info",
            ))
        return findings

    def check_file(self, ctx, path, st, accounts, seen_keys):
        names = [n for n, _ in accounts]
        uids = {u for _, u in accounts}
        target_st = st
        evidence = []
        if stat.S_ISLNK(st.st_mode):
            evidence.append(Evidence(path, "심볼릭 링크 → {}".format(ctx.readlink(path))))
            target_st = ctx.stat(path, follow=True)
            if target_st is None:
                return None  # 대상이 없는 링크: sshd도 읽지 못한다
            if stat.S_ISDIR(target_st.st_mode):
                return None

        self.key_files += 1
        critical, warning = [], []
        if stat.S_ISREG(target_st.st_mode):
            keys = parse_keys(ctx.read_lines(path))
            self.key_count += len(keys)
        else:
            # FIFO 등을 열면 진단 도구가 멈출 수 있으므로 읽지 않는다
            keys = []
            warning.append("키 파일 자리에 일반 파일이 아닌 것이 있다 (읽지 않음)")

        if keys:
            kinds = {}
            for name, uid in accounts:
                kinds.setdefault(account_kind(name, uid), []).append(name)
            if "uid0" in kinds:
                critical.append("root 외 UID 0 계정({})에 키가 있다".format(", ".join(kinds["uid0"])))
            if "system" in kinds:
                text = "시스템 계정({})에 키가 있다".format(", ".join(kinds["system"]))
                if all("command=" in k[4] for k in keys):
                    warning.append(text + " — 모든 키에 command= 강제 명령이 걸려 있어 위험으로 낮춤")
                else:
                    critical.append(text)

        if target_st.st_mode & 0o022:
            warning.append("키 파일을 다른 사용자가 쓸 수 있다 (권한 {:o})".format(stat.S_IMODE(target_st.st_mode)))
        ssh_dir = posixpath.dirname(path)
        dir_st = ctx.stat(ssh_dir, follow=True)
        if dir_st is not None and dir_st.st_mode & 0o022 and not dir_st.st_mode & stat.S_ISVTX:
            warning.append("{}를 다른 사용자가 쓸 수 있다 (권한 {:o})".format(ssh_dir, stat.S_IMODE(dir_st.st_mode)))
        if target_st.st_uid not in uids and target_st.st_uid != 0:
            warning.append("키 파일 소유자(UID {})가 이 파일을 쓰는 계정이 아니다".format(target_st.st_uid))

        when, future = timefmt.describe(target_st.st_mtime, ctx.now)
        if future:
            warning.append("파일 변경 시각이 미래다 (시각 조작 흔적)")

        if not keys and not warning:
            return None

        for no, ktype, fp, comment, options in keys:
            detail = "{}행: {} {}".format(no, ktype, fp or "(지문 계산 불가)")
            if comment:
                detail += " ({})".format(comment)
            if options:
                detail += " [옵션: {}]".format(options)
            evidence.append(Evidence(path, detail))
            if fp:
                places = seen_keys.setdefault(fp, [])
                if all(p != path for p, _ in places):
                    places.append((path, names))
        evidence.append(Evidence(path, "파일 변경: {}".format(when)))

        if critical:
            severity = "critical"
        elif warning:
            severity = "warning"
        else:
            severity = "info"
        conditions = critical + warning
        reason = "'{}' 계정의 SSH 키 {}개".format(", ".join(names), len(keys))
        reason += ": " + "; ".join(conditions) if conditions else "가 등록되어 있다."
        return self.finding(
            reason=reason,
            next_steps="키 주석과 지문으로 누구의 키인지 확인하고, auth.log에서 이 지문으로 로그인한 기록"
                       "('Accepted publickey ... SHA256:...')을 찾는다.",
            evidence=evidence,
            severity=severity,
        )
