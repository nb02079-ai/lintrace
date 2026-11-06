"""PER-02 패키지에 속하지 않는 systemd 서비스·타이머.

읽는 곳: 시스템 유닛 /etc/systemd/system, /run/systemd/system, /usr/local/lib/systemd/system, /lib·/usr/lib/systemd/system
(덮어쓰기 파일 '<유닛>.d/*.conf' 포함), 사용자 유닛 /etc/systemd/user, /lib·/usr/lib/systemd/user, 홈의 .config/systemd/user.

판정
- 위험: 패키지에 속하지 않거나 패키지 원본과 다른 유닛·덮어쓰기 파일이 명령(Exec*)을 실행한다
- 심각: 실행 명령이 의심 명령(내려받아 실행·리버스 셸 등)이거나, 실행 대상이 임시 폴더·숨김 경로·사용자 홈에 있음
- 심각: root로 도는 유닛 파일이나 그 실행 대상을 일반 사용자가 소유하거나 쓸 수 있음 — 그 사용자가 내용을 바꿔
  root 권한을 얻는다 (lin.security debug.service, 2026-11-06 정답)
예외 (범위에 개수만)
- 실행 지시어가 없는 유닛 (snapd의 snap-*.mount 등 — 명령을 실행하지 못함)
- /run에 생성된 파일 중 실행 대상이 모두 셸·인터프리터가 아닌 패키지 실행 파일 (netplan 등 생성기)
활성화 여부(.wants·.requires 링크)는 근거에 표시한다.
"""
import posixpath
import shlex

from .base import Check, Context, Evidence
from .persist import (Item, exec_conditions, file_evidence, file_state, group, homes, owner_issue, packaged_binary,
                      regular, unique_dirs)
from .scriptscan import scan_command

SYSTEM_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
               "/lib/systemd/system", "/usr/lib/systemd/system"]
USER_DIRS = ["/etc/systemd/user", "/lib/systemd/user", "/usr/lib/systemd/user"]
SUFFIXES = (".service", ".socket", ".timer", ".path", ".mount", ".automount", ".swap", ".target", ".slice",
            ".scope")
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
             "ExecCondition")


def parse_unit(lines):
    """(Exec 목록 [(줄 번호, 키, 값)], User 값)"""
    execs, user = [], None
    for no, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s[0] in "#;[" or "=" not in s:
            continue
        key, value = [x.strip() for x in s.split("=", 1)]
        if key in EXEC_KEYS:
            if value:
                execs.append((no, key, value))
            else:
                execs = [e for e in execs if e[1] != key]  # 'ExecStart=' — 앞의 값을 지움
        elif key == "User":
            user = value
    return execs, user


def exec_target(value):
    """'-/usr/bin/x --a' → '/usr/bin/x' (앞의 특수 문자 @-:+! 제거)"""
    v = value.lstrip("@-:+!")
    try:
        toks = shlex.split(v)
    except ValueError:
        toks = v.split()
    return toks[0] if toks else ""


class Per02(Check):
    id = "PER-02"
    title = "패키지에 속하지 않는 systemd 서비스·타이머"
    severity = "warning"
    attack = "T1543.002"

    def run(self, ctx: Context):
        sys_dirs = unique_dirs(ctx, SYSTEM_DIRS)
        user_dirs = unique_dirs(ctx, USER_DIRS)
        home_dirs = unique_dirs(ctx, [posixpath.join(h, ".config/systemd/user") for _, h in homes(ctx)])
        all_dirs = sys_dirs + user_dirs + home_dirs
        real_dirs = {ctx.realpath(d) for d in all_dirs}
        enabled = self.enabled_names(ctx, all_dirs)

        self.counts = {"units": 0, "foreign": 0, "noexec": 0, "generated": 0, "dropins": 0}
        items = []
        for d in all_dirs:
            system = d in sys_dirs
            for name in ctx.list_dir(d):
                path = posixpath.join(d, name)
                if name.endswith(".d") and name[:-2].endswith(SUFFIXES):
                    for conf in ctx.list_dir(path):
                        if conf.endswith(".conf"):
                            self.counts["dropins"] += 1
                            it = self.check_file(ctx, posixpath.join(path, conf), system, enabled, name[:-2])
                            if it:
                                items.append(it)
                    continue
                if not name.endswith(SUFFIXES):
                    continue
                link = ctx.readlink(path)
                if link is not None:
                    real = ctx.realpath(path)
                    if link == "/dev/null" or real == "/dev/null" or posixpath.dirname(real) in real_dirs:
                        continue  # 마스크, 또는 다른 유닛 폴더의 별칭
                if not regular(ctx, path):
                    continue
                self.counts["units"] += 1
                it = self.check_file(ctx, path, system, enabled, None)
                if it:
                    items.append(it)

        findings = group(self, items,
                         "유닛이 무엇을 실행하는지와 누가 만들었는지 확인한다 ('systemctl status 유닛', 'systemctl cat 유닛'). "
                         "필요 없으면 'systemctl disable --now 유닛'으로 멈추기 전에 실행 파일을 보존한다(--out). 일반 사용자가 "
                         "소유한 root 유닛은 소유자를 root로 바꾸고 그 사용자의 활동을 확인한다.", "systemd 유닛")
        c = self.counts
        notes = ["패키지 밖·원본과 다름 {}개".format(c["foreign"])]
        if c["noexec"]:
            notes.append("그중 실행 지시어 없음 {}개".format(c["noexec"]))
        if c["generated"]:
            notes.append("/run 생성 파일 {}개".format(c["generated"]))
        self.scope = "유닛 {}개, 덮어쓰기 파일 {}개 ({})".format(c["units"], c["dropins"], ", ".join(notes))
        return findings

    @staticmethod
    def enabled_names(ctx, dirs):
        names = {}
        for d in dirs:
            for sub in ctx.list_dir(d):
                if sub.endswith((".wants", ".requires")):
                    for n in ctx.list_dir(posixpath.join(d, sub)):
                        names.setdefault(n, posixpath.join(d, sub, n))
        return names

    def check_file(self, ctx, path, system, enabled, dropin_of):
        state, pkg = file_state(ctx, path)
        lines = ctx.read_lines(ctx.realpath(path), missing_ok=True)
        execs, user = parse_unit(lines)
        runs_as_root = system and user in (None, "", "root", "0")
        conditions = []
        if runs_as_root and state != "unpackaged":
            issue = owner_issue(ctx, path)  # 패키지 유닛이라도 일반 사용자가 쓸 수 있으면 권한 상승
            if issue:
                conditions.append(("critical", issue))
        if state in ("unpackaged", "modified"):
            self.counts["foreign"] += 1
            if not execs:
                self.counts["noexec"] += 1
            elif path.startswith("/run/") and all(packaged_binary(ctx, exec_target(v)) for _, _, v in execs) \
                    and not any(scan_command(v) for _, _, v in execs):
                self.counts["generated"] += 1
            else:
                what = "패키지 서비스 {}의 실행 명령을 바꾸는 덮어쓰기 파일".format(dropin_of) if dropin_of else \
                    "패키지에 속하지 않는 유닛이 명령을 실행한다" if state == "unpackaged" else \
                    "패키지 원본과 다른 유닛이 명령을 실행한다"
                conditions.append(("warning", what + ("" if system else " (사용자 유닛)")))
                if runs_as_root:
                    issue = owner_issue(ctx, path)
                    if issue:
                        conditions.append(("critical", issue))
                for _, _, v in execs:
                    conditions += exec_conditions(ctx, v, exec_target(v), runs_as_root)
        if not conditions:
            return None
        ev = file_evidence(ctx, path, state, pkg)
        for no, key, v in execs[:5]:
            ev.append(Evidence(path, "{}행: {}={}".format(no, key, v)))
        ev.append(Evidence(path, "실행 계정: {}".format(user or ("root (User= 없음)" if system else "유닛 주인"))))
        unit = dropin_of or posixpath.basename(path)
        ev.append(Evidence(enabled.get(unit, path), "활성화됨 — 부팅·로그인 때 실행" if unit in enabled else
                           "활성화 링크 없음 (다른 유닛·타이머가 부를 수 있음)"))
        # 중복 제거 (같은 조건이 여러 Exec 줄에서 나올 수 있음)
        seen, uniq = set(), []
        for c in conditions:
            if c not in seen:
                seen.add(c)
                uniq.append(c)
        return Item(path, uniq, ev)
