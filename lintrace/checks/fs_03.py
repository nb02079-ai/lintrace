"""FS-03 capabilities가 부여된 파일.

file capability(security.capability 확장 속성)는 SUID 없이 root 권한 일부를 준다. 'setcap cap_setuid+ep
/usr/bin/python3'처럼 셸 탈출 프로그램에 붙이면 SUID와 똑같은 권한 상승 통로가 되고, getcap을 따로 돌리지
않으면 눈에 띄지 않는다.

판정 (2026-11-06 정답 반영)
- 정상(범위에 개수): 패키지 원본과 같고 셸 탈출 프로그램이 아닌 파일 — 패키지 설치 스크립트가 붙인 것
  (ping·mtr-packet의 net_raw, gst-ptp-helper, snapd의 snap-confine 등)
- 위험: 패키지에 속하지 않거나 원본과 다른 파일의 capability
- 심각: 셸 탈출 프로그램(FS-02와 같은 목록)에 위험한 capability — 패키지 소속과 무관
  (패키지는 셸 탈출 프로그램에 capability를 붙이지 않는다)
"""
import struct

from .base import Check, Context, Evidence, Unavailable
from ..collectors.filewalk import filewalk, require_root
from .fs_02 import SUID_ESCAPE, norm_name
from .persist import Item, file_evidence, file_state, group

NAMES = ["chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
         "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
         "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
         "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
         "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
         "checkpoint_restore"]
DANGEROUS = {"chown", "dac_override", "dac_read_search", "fowner", "setgid", "setuid", "sys_admin", "sys_ptrace",
             "sys_module", "sys_rawio", "setfcap", "setpcap"}


def decode(raw):
    """vfs_cap_data → (capability 이름 목록, 'cap_x,cap_y+ep' 표기). 해석 못 하면 (None, 원본 16진수)."""
    if len(raw) < 12:
        return None, raw.hex()
    magic = struct.unpack("<I", raw[:4])[0]
    version, effective = magic & 0xFF000000, magic & 1
    permitted, inheritable = struct.unpack("<II", raw[4:12])
    if version in (0x02000000, 0x03000000) and len(raw) >= 20:
        p_hi, i_hi = struct.unpack("<II", raw[12:20])
        permitted |= p_hi << 32
        inheritable |= i_hi << 32
    elif version != 0x01000000:
        return None, raw.hex()
    caps = permitted | inheritable
    names = [NAMES[i] if i < len(NAMES) else "cap_{}".format(i) for i in range(64) if caps >> i & 1]
    flags = ("e" if effective else "") + ("i" if inheritable else "") + ("p" if permitted else "")
    return names, "{}+{}".format(",".join("cap_" + n for n in names), flags)


class Fs03(Check):
    id = "FS-03"
    title = "capabilities가 부여된 파일"
    severity = "warning"
    attack = "T1548"

    def run(self, ctx: Context):
        w = filewalk(ctx)
        if require_root(w):
            raise Unavailable("디렉터리 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(w.denied)))
        items, normal = [], []
        for path, st, raw in w.caps:
            names, text = decode(raw)
            state, pkg = file_state(ctx, path)
            escape = norm_name(path) in SUID_ESCAPE
            danger = sorted(set(names or []) & DANGEROUS)
            cond = []
            if escape and (danger or names is None):
                cond.append(("critical", "셸 탈출이 되는 프로그램에 위험한 capability({})가 붙었다 — 실행하는 사람이 root "
                                         "권한을 얻을 수 있다".format(", ".join(danger) or "해석 불가")))
            if state in ("unpackaged", "modified"):
                cond.append(("warning", "{} 파일에 capability가 붙었다".format(
                    "패키지에 속하지 않는" if state == "unpackaged" else "패키지 원본과 다른")))
            if not cond:
                normal.append(posixpath_name(path))
                continue
            ev = [Evidence(path, "capability: {}".format(text))] + file_evidence(ctx, path, state, pkg)
            ev.append(Evidence(path, "SHA-256: {}".format(ctx.sha256(path) or "계산 불가")))
            items.append(Item(path, cond, ev))
        findings = group(self, items, "의도한 설정인지 확인하고 아니면 'setcap -r 파일'로 지운다. 누가 붙였는지는 명령 기록의 setcap과 "
                                      "파일의 ctime(속성을 바꾸면 바뀜)으로 본다.", "capability 파일")
        self.scope = "파일 {:,}개 중 capability {}개 (패키지 원본 {}개{})".format(
            w.files_seen, len(w.caps), len(normal), ": " + ", ".join(normal[:6]) if normal else "")
        return findings


def posixpath_name(path):
    return path.rsplit("/", 1)[-1]
