"""FS-07 웹 서버 계정이 만든 웹 루트 스크립트.

웹쉘은 웹 서버 프로세스가 쓰므로 웹 서버 계정(www-data 등) 소유로 남는다. 코드가 root 소유로 배포된 웹
루트라면 웹 계정 소유 스크립트는 웹 서버가 직접 만든 파일이다.

판정 (2026-11-06 결정 — 웹 루트별 스크립트 소유 비율)
- 웹 루트의 스크립트가 절반 넘게 root 등 다른 계정 소유: 웹 계정 소유 스크립트 → 위험
- 절반 이상이 웹 계정 소유(WordPress를 'chown -R www-data'로 설치한 경우 등 — 24.04 정답 1,518개 전부):
  파일별로는 구분할 수 없으므로 참고 1건 — 웹 서버가 자기 코드를 고칠 수 있어 침입 한 번이 곧 지속성이 된다.
  웹쉘 판정은 FS-06 내용 검사가 한다.
"""
import posixpath
import re

from .base import Check, Context, Evidence
from .fs_06 import Fs06, SCRIPT_EXT, config_paths, ext_of
from .persist import Item, file_evidence, group

WEB_USERS = {"www-data", "nginx", "apache", "httpd", "http", "wwwrun", "lighttpd", "www"}


def web_uids(ctx):
    names = set(WEB_USERS)
    for path in config_paths(ctx, ["/etc/nginx/nginx.conf"]):
        for line in ctx.read_lines(path, missing_ok=True):
            m = re.match(r"^\s*user\s+([\w.-]+)", line)
            if m:
                names.add(m.group(1))
    for line in ctx.read_lines("/etc/apache2/envvars", missing_ok=True):
        m = re.match(r"^\s*export\s+APACHE_RUN_USER=([\w.-]+)", line)
        if m:
            names.add(m.group(1))
    out = {}
    for line in ctx.read_lines("/etc/passwd", missing_ok=True):
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] in names:
            out[int(parts[2])] = parts[0]
    return out


class Fs07(Check):
    id = "FS-07"
    title = "웹 서버 계정이 만든 웹 루트 스크립트"
    severity = "warning"
    attack = "T1505.003"

    def run(self, ctx: Context):
        uids = web_uids(ctx)
        fs06 = Fs06()
        roots = fs06.web_roots(ctx)
        findings, notes, denied = [], [], []
        for root in roots:
            scripts = [(p, st) for p, st in fs06.walk(ctx, root, denied) if ext_of(p) in SCRIPT_EXT]
            mine = [(p, st) for p, st in scripts if st.st_uid in uids]
            notes.append("{} 스크립트 {:,}개 중 웹 계정 소유 {:,}개".format(root, len(scripts), len(mine)))
            if not mine:
                continue
            if len(mine) * 2 >= len(scripts):
                dirs = {}
                for p, _ in mine:
                    d = posixpath.dirname(p)
                    dirs[d] = dirs.get(d, 0) + 1
                top = sorted(dirs.items(), key=lambda x: -x[1])[:5]
                findings.append(self.finding(
                    reason="웹 루트 {}의 스크립트 {:,}개 중 {:,}개({}%)가 웹 서버 계정({}) 소유다 — 웹 서버가 자기 코드를 고칠 수 "
                           "있어, 웹 취약점 한 번이 곧 코어 파일 변조·지속성이 된다. 이 상태에서는 소유자로 웹쉘을 가릴 수 없다 "
                           "(FS-06 내용 검사로 판단)".format(root, len(scripts), len(mine), len(mine) * 100 // len(scripts),
                                                            ", ".join(sorted(set(uids.values())))),
                    next_steps="코드는 root(또는 배포 계정) 소유로 두고 웹 계정에는 업로드·캐시 폴더만 쓰기를 허용한다 "
                               "(예: 'chown -R root:root 웹루트; chown -R www-data 웹루트/wp-content/uploads').",
                    evidence=[Evidence(d, "웹 계정 소유 스크립트 {}개".format(n)) for d, n in top],
                    severity="info"))
                continue
            items = []
            for p, st in mine:
                items.append(Item(p, [("warning", "웹 서버 계정({})이 소유한 스크립트 — 다른 코드는 다른 계정 소유인데 이것만 "
                                                  "웹 서버가 만들었다".format(uids[st.st_uid]))],
                                  file_evidence(ctx, p, "unpackaged", None)[1:] +
                                  [Evidence(p, "SHA-256: {}".format(ctx.sha256(p) or "계산 불가"))]))
            findings += group(self, items, "내용을 확인하고(FS-06 결과와 함께) 웹 접근 로그에서 이 파일 요청을 찾는다(CMD-03). 웹쉘이면 "
                                           "보존한 뒤(--out) 지우고 업로드 경로를 막는다.", "웹 계정 소유 스크립트")
        self.scope = "; ".join(notes) if notes else "웹 루트 없음"
        if not uids:
            self.scope += " (웹 서버 계정 없음)"
        return findings
