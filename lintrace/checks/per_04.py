"""PER-04 셸 초기화 파일의 의심 구문.

셸 초기화 파일은 로그인·새 셸마다 실행된다. 공격자는 여기에 명령을 넣어 지속성을 얻거나, sudo·su를
가짜 함수로 바꿔 비밀번호를 가로챈다.

읽는 곳: /etc/profile, /etc/profile.d/*, /etc/bash.bashrc, /etc/zsh/{zshenv,zprofile,zshrc,zlogin},
모든 사용자 홈과 /root의 .bashrc·.profile·.bash_profile·.bash_login·.bash_logout·.zshrc·.zprofile·.zshenv

판정
- 위험: sudo·su·ssh·passwd 등을 alias·함수로 바꿔 치기, LD_PRELOAD 설정, PROMPT_COMMAND·'trap … DEBUG'로
  명령마다 실행, PATH 맨 앞에 임시·숨김·현재 폴더, 명령 기록 끄기(unset HISTFILE, HISTFILE=/dev/null,
  HISTSIZE=0 — LOG-03과 함께 봄)
- 심각: 의심 명령 (내려받아 실행·리버스 셸·인코딩 풀어 실행·임시 폴더 실행)
원본 비교: /etc/profile은 /usr/share/base-files/profile, 홈의 파일은 /etc/skel의 같은 파일과 비교해 추가된 줄을
근거로 보여준다 (원본과 같은 파일의 구문은 배포판 기본값이므로 판정하지 않는다).
"""
import difflib
import posixpath
import re

from .base import Check, Context, Evidence
from .persist import Item, file_evidence, file_state, group, homes, regular
from .scriptscan import TEMP_DIRS, hidden_system_path, scan_command

SYSTEM_FILES = ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc",
                "/etc/zsh/zlogin", "/etc/environment"]
PROFILE_D = "/etc/profile.d"
HOME_FILES = [".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile",
              ".zshenv"]
ORIGINALS = {"/etc/profile": "/usr/share/base-files/profile"}
SKEL = "/etc/skel"
ROOT_ORIGINALS = {".bashrc": "/usr/share/base-files/dot.bashrc", ".profile": "/usr/share/base-files/dot.profile"}

# 비밀번호를 받는 명령 (ls 등은 색 표시 alias가 흔해 넣지 않는다)
SENSITIVE = r"(?:sudo|su|ssh|scp|sftp|passwd|login|doas|pkexec)"
PATTERNS = [
    (re.compile(r"^\s*alias\s+" + SENSITIVE + r"\s*="), "명령 {}를 alias로 바꿔 친다"),
    (re.compile(r"^\s*(?:function\s+)?" + SENSITIVE + r"\s*\(\s*\)|^\s*function\s+" + SENSITIVE + r"\b"),
     "명령 {}를 같은 이름의 함수로 바꿔 친다"),
    (re.compile(r"\bLD_PRELOAD\s*="), "LD_PRELOAD를 설정한다 — 이후 실행하는 모든 프로그램에 라이브러리를 끼워 넣는다"),
    (re.compile(r"\bPROMPT_COMMAND\s*="), "PROMPT_COMMAND를 설정한다 — 프롬프트마다 명령이 실행된다"),
    (re.compile(r"\btrap\b.*\bDEBUG\b"), "'trap … DEBUG'로 명령마다 다른 명령을 실행한다"),
    (re.compile(r"^\s*unset\s+(?:-v\s+)?HISTFILE\b|\bHISTFILE\s*=\s*[\"']?/dev/null|\bHIST(?:FILE)?SIZE\s*=\s*[\"']?0[\"']?\s*(?:$|;)"
                r"|\bset\s+\+o\s+history\b"),
     "명령 기록을 끈다 (LOG-03과 함께 확인)"),
]
NAME = re.compile(r"(?:alias\s+|function\s+|^\s*)(" + SENSITIVE + r")\b")
PATH_FIRST = re.compile(r"\bPATH\s*=\s*[\"']?([^:\"'\s]*):")


def added_lines(ctx, path, original):
    """원본에 없는 줄의 번호 집합. 원본이 없으면 None (전체를 본다)."""
    if not regular(ctx, original):
        return None
    base = ctx.read_lines(original)
    cur = ctx.read_lines(path)
    added = set()
    for tag, _, _, j1, j2 in difflib.SequenceMatcher(None, base, cur, autojunk=False).get_opcodes():
        if tag in ("replace", "insert"):
            added.update(range(j1 + 1, j2 + 1))
    return added


def line_conditions(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return []
    out = []
    for rx, text in PATTERNS:
        if rx.search(s):
            m = NAME.search(s)
            out.append(("warning", text.format(m.group(1) if m else "")))
    m = PATH_FIRST.search(s)
    if m:
        first = m.group(1)
        if first in ("", ".") or first.startswith(TEMP_DIRS) or (first + "/").startswith(TEMP_DIRS) \
                or hidden_system_path(first + "/x"):
            out.append(("warning", "PATH 맨 앞에 {}를 둔다 — 같은 이름의 가짜 명령이 먼저 실행된다".format(first or "현재 폴더")))
    out += scan_command(s)
    return out


class Per04(Check):
    id = "PER-04"
    title = "셸 초기화 파일의 의심 구문"
    severity = "warning"
    attack = "T1546.004"

    def run(self, ctx: Context):
        targets = [(p, ORIGINALS.get(p)) for p in SYSTEM_FILES]
        for name in ctx.list_dir(PROFILE_D):
            targets.append((posixpath.join(PROFILE_D, name), None))
        for _, home in homes(ctx):
            for name in HOME_FILES:
                # root의 .bashrc·.profile은 /etc/skel이 아니라 base-files의 dot.* 에서 온다
                original = ROOT_ORIGINALS.get(name) if home == "/root" else None
                if not original or not regular(ctx, original):
                    original = posixpath.join(SKEL, name)
                targets.append((posixpath.join(home, name), original))

        items, files, same_as_original = [], 0, 0
        seen = set()
        for path, original in targets:
            if path in seen or not regular(ctx, path):
                continue
            seen.add(path)
            files += 1
            state, pkg = file_state(ctx, path)
            if state == "same":
                continue  # 패키지 원본 그대로 (배포판 기본값)
            added = added_lines(ctx, path, original) if original else None
            if added is not None and not added:
                same_as_original += 1
                continue
            conds, ev_lines = [], []
            for no, line in enumerate(ctx.read_lines(path), start=1):
                if added is not None and no not in added:
                    continue
                c = line_conditions(line)
                if c:
                    conds += c
                    ev_lines.append(Evidence(path, "{}행: {}".format(no, line.strip()[:200])))
            if not conds:
                continue
            ev = file_evidence(ctx, path, state, pkg)
            if added is not None:
                ev.append(Evidence(original, "원본 {}와 비교해 추가·변경된 줄 {}개".format(original, len(added))))
            uniq = []
            for c in conds:
                if c not in uniq:
                    uniq.append(c)
            items.append(Item(path, uniq, ev + ev_lines[:8]))

        findings = group(self, items, "해당 줄을 누가 언제 넣었는지 확인하고(명령 기록, 파일 변경 시각) 지운다. 함수·alias로 바꿔 친 "
                                      "명령은 비밀번호를 가로챘을 수 있으므로 그 계정의 비밀번호를 바꾼다.", "셸 초기화 파일")
        self.scope = "초기화 파일 {}개 (원본과 같은 홈·시스템 파일 {}개)".format(files, same_as_original)
        return findings
