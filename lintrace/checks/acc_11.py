"""ACC-11 PAM 모듈 변조.

PAM은 로그인·sudo·su의 비밀번호 검사를 맡는다. 공격자는 모듈을 바꿔치기하거나(pam_unix.so에 고정
비밀번호 넣기), 설정에 통과용 줄을 넣어(auth sufficient pam_permit.so) 아무 비밀번호로나 들어온다.

판정 (심각)
- PAM 설정이 부르는 모듈이 어느 패키지에도 속하지 않음 (usrmerge 별칭을 맞춰 dpkg 기록과 비교)
- 모듈 해시가 설치 당시 dpkg 기록(md5sums)과 다름
- auth 스택(@include·include·substack을 펼친 순서)에서 pam_deny.so보다 앞에 pam_permit.so가
  required·requisite·optional 이외의 제어로 나옴 — Ubuntu 기본은 deny 뒤에 required로만 쓴다
  (sufficient나 [success=…]이면 비밀번호 검사를 건너뛰는 뒷문)
- pam_exec.so가 임시 폴더·홈 아래 프로그램을 실행
"""
import hashlib
import posixpath
import re
import stat

from ..collectors.packages import packages
from .base import Check, Context, Evidence

PAM_DIR = "/etc/pam.d"
MODULE_DIRS = ["/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security"]
USER_AREAS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")
SAFE_PERMIT_CONTROLS = {"required", "requisite", "optional"}
LINE = re.compile(r"^(-?)(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$", re.I)
MAX_DEPTH = 8


def module_dirs(ctx):
    dirs = list(MODULE_DIRS)
    for base in ("/lib", "/usr/lib"):
        for name in ctx.list_dir(base):
            if name.endswith("-linux-gnu"):
                dirs.append(posixpath.join(base, name, "security"))
    return dirs


class PamLine:
    __slots__ = ("path", "no", "text", "type", "control", "module", "args")

    def __init__(self, path, no, text, m):
        self.path, self.no, self.text = path, no, text
        self.type = m.group(2).lower()
        self.control = m.group(3)
        self.module = m.group(4)
        self.args = m.group(5)


class Acc11(Check):
    id = "ACC-11"
    title = "PAM 모듈 변조"
    severity = "critical"
    attack = "T1556.003"

    def run(self, ctx: Context):
        if ctx.stat(PAM_DIR, follow=True) is None:
            self.scope = "PAM 설정 없음"
            return []
        services = [n for n in ctx.list_dir(PAM_DIR)
                    if is_file(ctx.stat(posixpath.join(PAM_DIR, n), follow=True))]
        self.dirs = module_dirs(ctx)
        self.cache = {}
        lines = []
        for name in services:
            lines += self.read(ctx, posixpath.join(PAM_DIR, name))
        db = packages(ctx)

        findings, modules, checked = [], {}, 0
        for ln in lines:
            modules.setdefault(ln.module, []).append(ln)
        for module in sorted(modules):
            path = self.resolve(ctx, module)
            if path is None:
                continue  # 없는 모듈은 PAM이 불러오지 못한다 ('-'로 시작하는 선택 줄 등)
            f = self.check_module(ctx, db, module, path, modules[module])
            checked += 1
            if f:
                findings.append(f)
        for name in services:
            findings += self.check_stack(ctx, name)
        for ln in lines:
            if posixpath.basename(ln.module) == "pam_exec.so":
                progs = [a for a in ln.args.split() if a.startswith("/")]
                bad = [p for p in progs if p.startswith(USER_AREAS)]
                if bad:
                    findings.append(self.finding(
                        reason="pam_exec.so가 {}에서 {}를 실행한다 — 로그인할 때마다 임시 폴더·홈의 프로그램이 돈다".format(
                            ln.path, ", ".join(bad)),
                        next_steps="그 프로그램을 보존하고 내용을 확인한다 (비밀번호를 가로채 저장하는 경우가 많다).",
                        evidence=[Evidence(ln.path, "{}행: {}".format(ln.no, ln.text))],
                    ))
        dedup, seen = [], set()
        for f in findings:
            if f.reason not in seen:
                seen.add(f.reason)
                dedup.append(f)
        self.scope = "PAM 설정 {}개, 모듈 {}개{}".format(
            len(services), checked, "" if db.available else " (dpkg 정보 없음 — 소속·해시 비교 못 함)")
        return dedup

    # --- 읽기 ---

    def read(self, ctx, path):
        """설정 파일 한 개의 줄 (include를 펼치지 않음). 결과는 저장해 둔다."""
        if path in self.cache:
            return self.cache[path]
        out = []
        for no, raw in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
            s = raw.split("#", 1)[0].strip()
            if not s:
                continue
            m = LINE.match(s)
            if m:
                out.append(PamLine(path, no, s, m))
        self.cache[path] = out
        return out

    def stack(self, ctx, path, kind, depth=0):
        """type이 kind인 줄을 실제 실행 순서로 (@include, include, substack을 펼쳐서)."""
        if depth > MAX_DEPTH:
            return []
        out = []
        for no, raw in enumerate(ctx.read_lines(path, missing_ok=True), start=1):
            s = raw.split("#", 1)[0].strip()
            if s.startswith("@include"):
                parts = s.split()
                if len(parts) > 1:
                    out += self.stack(ctx, posixpath.join(PAM_DIR, parts[1]), kind, depth + 1)
                continue
            m = LINE.match(s)
            if not m or m.group(2).lower() != kind:
                continue
            if m.group(3).lower() in ("include", "substack"):
                out += self.stack(ctx, posixpath.join(PAM_DIR, m.group(4)), kind, depth + 1)
            else:
                out.append(PamLine(path, no, s, m))
        return out

    def resolve(self, ctx, module):
        if module.startswith("/"):
            return module if ctx.stat(module, follow=True) is not None else None
        for d in self.dirs:
            p = posixpath.join(d, module)
            if ctx.stat(p, follow=True) is not None:
                return p
        return None

    # --- 판정 ---

    def check_module(self, ctx, db, module, path, uses):
        if not db.available:
            return None
        real = ctx.realpath(path)
        where = [Evidence(u.path, "{}행: {}".format(u.no, u.text)) for u in uses[:2]]
        pkg = db.owner(path) or db.owner(real)
        if pkg is None:
            return self.finding(
                reason="PAM 모듈 {}({})이 어느 패키지에도 속하지 않는다 — 직접 넣은 모듈".format(module, real),
                next_steps="모듈 파일을 보존하고(--out) 문자열·심볼을 확인한다. 'dpkg -S'로 소속을 다시 확인하고, "
                           "설정에서 빼기 전에 다른 관리자 세션을 열어 둔다 (잠금 방지).",
                evidence=where + [Evidence(real, "SHA-256: {}".format(ctx.sha256(real) or "계산 불가"))],
            )
        expected = db.md5(path) or db.md5(real)
        if expected is None:
            return None
        actual = md5_of(ctx, real)
        if actual and actual != expected[0]:
            return self.finding(
                reason="PAM 모듈 {}({})의 내용이 설치 당시와 다르다 (패키지 {}) — 바꿔치기한 모듈".format(module, real, pkg),
                next_steps="모듈 파일을 보존하고(--out) 'dpkg --verify {}'로 확인한 뒤 패키지를 다시 설치한다. "
                           "바뀐 시점 전후의 로그인 기록을 확인한다.".format(pkg),
                evidence=where + [Evidence(real, "MD5 지금 {} / dpkg 기록 {}".format(actual, expected[0])),
                                  Evidence(real, "SHA-256: {}".format(ctx.sha256(real) or "계산 불가"))],
            )
        return None

    def check_stack(self, ctx, name):
        out = []
        for ln in self.stack(ctx, posixpath.join(PAM_DIR, name), "auth"):
            base = posixpath.basename(ln.module)
            if base == "pam_deny.so":
                break
            if base == "pam_permit.so" and ln.control.lower() not in SAFE_PERMIT_CONTROLS:
                out.append(self.finding(
                    reason="{}의 인증 순서에서 pam_permit.so가 pam_deny.so보다 앞에 '{}'로 나온다 — "
                           "비밀번호 검사를 건너뛰고 통과시키는 뒷문".format(posixpath.join(PAM_DIR, name), ln.control),
                    next_steps="이 줄을 지우기 전에 다른 root 세션을 열어 두고, 설정이 바뀐 시점 뒤의 로그인 기록을 확인한다.",
                    evidence=[Evidence(ln.path, "{}행: {}".format(ln.no, ln.text))],
                ))
        return out


def is_file(st):
    return st is not None and stat.S_ISREG(st.st_mode)


def md5_of(ctx, path):
    h = hashlib.md5()
    try:
        with open(ctx.path(path), "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()
