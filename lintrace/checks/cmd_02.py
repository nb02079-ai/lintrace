"""CMD-02 history의 리버스 셸·인코딩 명령.

판정
- 심각: 명령 기록에 리버스 셸(/dev/tcp, nc -e, socat exec, 파이썬·펄 소켓 등)이나 인코딩을 풀어 실행하는 명령
  (base64 -d | sh 등 — PER-01과 같은 패턴)
- 위험: 로그인 셸이 없는 서비스 계정(www-data 등)에 명령 기록이 있음 — 웹쉘 등으로 그 계정의 셸을 얻어 쓴 흔적
"""
from ..collectors.history import history
from .base import Check, Context, Evidence
from .cmd_01 import when
from .persist import Item, group
from .scriptscan import B64_EXEC, REVERSE_SHELL


class Cmd02(Check):
    id = "CMD-02"
    title = "history의 리버스 셸·인코딩 명령"
    severity = "critical"
    attack = "T1140"

    def run(self, ctx: Context):
        h = history(ctx)
        items, service = [], 0
        for user, path, count, nologin in h.files:
            cond, ev = [], []
            if nologin and count:
                service += 1
                cond.append(("warning", "로그인 셸이 없는 서비스 계정 '{}'에 명령 {}개가 기록돼 있다".format(user, count)))
            for e in h.of(path):
                hit = []
                if any(p.search(e.cmd) for p in REVERSE_SHELL):
                    hit.append("리버스 셸 형태의 명령")
                if any(p.search(e.cmd) for p in B64_EXEC):
                    hit.append("인코딩된 내용을 풀어 실행하는 명령")
                for text in hit:
                    cond.append(("critical", text))
                if hit:
                    ev.append(Evidence(path, "{}행 ({}): {}".format(e.lineno, when(e, ctx.now), e.cmd[:200])))
            if cond:
                uniq = []
                for c in cond:
                    if c not in uniq:
                        uniq.append(c)
                if nologin and not ev:
                    ev = [Evidence(path, "{}행: {}".format(e.lineno, e.cmd[:200])) for e in h.of(path)[-5:]]
                items.append(Item(path, uniq, ev[:15]))
        findings = group(self, items, "명령의 상대 주소·시각을 기록하고, 그 시각의 네트워크 연결(NET-02)·로그인(ACC-09)·웹 로그(CMD-03)와 "
                                      "맞춰 본다. 서비스 계정의 기록이면 그 계정으로 도는 웹 애플리케이션의 웹쉘(FS-06)을 찾는다.",
                         "명령 기록")
        self.scope = "명령 기록 파일 {}개, 명령 {:,}개 (서비스 계정 기록 {}개)".format(len(h.files), len(h.entries), service)
        return findings
