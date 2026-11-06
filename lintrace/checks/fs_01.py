"""FS-01 임시 디렉터리의 ELF 실행 파일.

/tmp, /var/tmp, /dev/shm은 누구나 쓸 수 있어 공격자가 내려받은 도구(채굴기, 백도어, 권한 상승 익스플로잇)를
두는 단골 위치다. 정상 프로그램은 실행 파일을 여기에 두지 않는다.

판정 (파일 앞 4바이트가 ELF)
- 위험: 임시 폴더에 ELF 실행 파일·공유 라이브러리가 있음
- 심각: 지금 실행 중(PRC-01과 같은 사건), 숨김 경로, SUID·SGID, /etc/ld.so.preload에 적힘
"""
import os
import posixpath
import stat
import struct

from ..collectors.processes import processes
from .base import Check, Context, Evidence, Unavailable
from .persist import Item, file_evidence, group

TEMP = ["/tmp", "/var/tmp", "/dev/shm"]
MAX_FILES = 200000


def elf_kind(head):
    if head[:4] != b"\x7fELF":
        return None
    if len(head) >= 18:
        e_type = struct.unpack("<H" if head[5:6] != b"\x02" else ">H", head[16:18])[0]
        if e_type == 2:
            return "ELF 실행 파일"
        if e_type == 3:
            return "ELF 실행 파일·공유 라이브러리(PIE·.so)"
    return "ELF 파일"


class Fs01(Check):
    id = "FS-01"
    title = "임시 디렉터리의 ELF 실행 파일"
    severity = "warning"
    attack = "T1105"

    def run(self, ctx: Context):
        seen, found, denied = 0, [], []
        for root in TEMP:
            if ctx.stat(root, follow=True) is None:
                continue
            stack = [root]
            while stack and seen < MAX_FILES:
                d = stack.pop()
                try:
                    entries = sorted(os.scandir(ctx.path(d)), key=lambda e: e.name)
                except PermissionError:
                    denied.append(d)
                    continue
                except (FileNotFoundError, NotADirectoryError):
                    continue
                for e in entries:
                    child = posixpath.join(d, e.name)
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(child)
                    elif stat.S_ISREG(st.st_mode):
                        seen += 1
                        kind = elf_kind(ctx.read_head(child, 18)) if st.st_size >= 4 else None
                        if kind:
                            found.append((child, st, kind))
        if denied and os.geteuid() != 0:
            raise Unavailable("임시 폴더 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(denied)))

        running = {}
        if found and ctx.root == "/":
            for p in processes(ctx).procs:
                if p.exe_path:
                    running.setdefault(p.exe_path.replace(" (deleted)", ""), p)
        preload = " ".join(ctx.read_lines("/etc/ld.so.preload", missing_ok=True))

        items = []
        for path, st, kind in found:
            cond = [("warning", "임시 폴더에 {}이 있다".format(kind))]
            if any(part.startswith(".") for part in path.split("/") if part):
                cond.append(("critical", "숨김 경로에 있다"))
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                cond.append(("critical", "SUID·SGID가 붙어 있다 (FS-02에서도 확인)"))
            p = running.get(path)
            if p is not None:
                cond.append(("critical", "지금 실행 중이다 (PID {} '{}', PRC-01에서도 확인)".format(p.pid, p.name)))
            if path in preload:
                cond.append(("critical", "/etc/ld.so.preload에 적혀 모든 프로그램에 끼워진다 (PER-05)"))
            ev = file_evidence(ctx, path, "unpackaged", None)[1:]
            ev.append(Evidence(path, "SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))
            ev.append(Evidence(path, "실행 권한: {}".format("있음" if st.st_mode & 0o111 else "없음")))
            items.append(Item(path, cond, ev))
        findings = group(self, items, "파일을 보존하고(--out) 해시로 정체를 확인한다(VirusTotal 등). 실행 중이면 끝내기 전에 "
                                      "프로세스의 네트워크 연결과 부모를 기록하고, 누가 언제 내려받았는지 명령 기록(CMD-01)·웹 로그를 본다.",
                         "ELF 파일")
        self.scope = "임시 폴더 파일 {:,}개 중 ELF {}개{}".format(
            seen, len(found), " (상한 {:,}개에서 멈춤)".format(MAX_FILES) if seen >= MAX_FILES else "")
        return findings
