"""2-B 프로세스·네트워크: PRC-02·04·05·06·07·08·09, NET-01·02·06, 소켓 수집기."""
import os
import unittest

from lintrace.checks.base import Context
from lintrace.checks.net_01 import Net01
from lintrace.checks.net_02 import Net02
from lintrace.checks.net_06 import Net06
from lintrace.checks.prc_02 import Prc02
from lintrace.checks.prc_04 import Prc04
from lintrace.checks.prc_05 import Prc05
from lintrace.checks.prc_06 import Prc06
from lintrace.checks.prc_07 import Prc07
from lintrace.checks.prc_08 import Prc08
from lintrace.checks.prc_09 import Prc09
from lintrace.collectors.nfs import KernelNfs, parse_rpcinfo
from lintrace.collectors.sockets import parse_addr

from test_prc_01 import NOW, LinkContext, ProcRootTest, proc

HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def inet(n, local, remote, st, uid, inode):
    return "   {}: {} {} {} 00000000:00000000 00:00000000 00000000 {:>5}        0 {} 1 0000000000000000 100 0 0 10 0\n".format(
        n, local, remote, st, uid, inode)


PACKAGED = ["/usr/sbin/sshd", "/usr/sbin/nginx", "/usr/lib/systemd/systemd-networkd", "/usr/bin/bash",
            "/usr/lib/systemd/systemd", "/usr/sbin/modprobe", "/usr/bin/tcpdump", "/usr/sbin/watchdog",
            "/usr/bin/nc.openbsd", "/usr/bin/python3.12"]

# Ubuntu 24.04 VM 정답을 줄인 것: sshd 22, nginx 80, systemd-networkd(packet LLDP + raw6 ipv6-icmp, DHCP 68),
# systemd 서비스의 표준 출력 unix 소켓, 검증자 SSH 세션. lin.security의 NFS 커널 소켓(inode 0)도 넣었다.
BASE_NET = {
    "/proc/net/tcp": HEAD + inet(0, "00000000:0016", "00000000:0000", "0A", 0, 8146) +
                     inet(1, "00000000:0050", "00000000:0000", "0A", 0, 9000) +
                     inet(2, "00000000:0801", "00000000:0000", "0A", 0, 0) +              # NFS 2049, 커널
                     inet(3, "4510A8C0:0016", "1210A8C0:EBDE", "01", 0, 9100),           # 192.168.16.69:22 ← .18
    "/proc/net/tcp6": HEAD,
    "/proc/net/udp": HEAD + inet(0, "4510A8C0:0044", "00000000:0000", "07", 998, 9200),  # DHCP 68
    "/proc/net/udp6": HEAD,
    "/proc/net/raw": HEAD,
    "/proc/net/raw6": HEAD + inet(0, "00000000000000000000000000000000:003A",
                                  "00000000000000000000000000000000:0000", "07", 998, 9300),
    "/proc/net/packet": "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
                        "ffff8d7b4452e800 3      3    88cc   2     1 0      998    6090\n",
    "/proc/net/unix": "Num       RefCount Protocol Flags    Type St Inode Path\n"
                      "0000000000000000: 00000002 00000000 00010000 0001 01 9454 /run/systemd/journal/stdout\n",
    "/var/lib/dpkg/info/base.list": "".join(p + "\n" for p in PACKAGED),
}
SSHD = proc(804, "sshd", 0, 1, "sshd: /usr/sbin/sshd -D", "/usr/sbin/sshd")
SSHD_SESSION = proc(1184, "sshd", 0, 804, "sshd: test [priv]", "/usr/sbin/sshd")
NGINX = proc(829, "nginx", 0, 1, "nginx: master process /usr/sbin/nginx", "/usr/sbin/nginx")
NETWORKD = proc(493, "systemd-network", 998, 1, "/usr/lib/systemd/systemd-networkd", "/usr/lib/systemd/systemd-networkd")
SYSTEMD = proc(1129, "systemd", 1000, 1, "/usr/lib/systemd/systemd --user", "/usr/lib/systemd/systemd")
BASE_FDS = {804: {"3": "socket:[8146]", "1": "socket:[9454]"}, 1184: {"4": "socket:[9100]"},
            829: {"5": "socket:[9000]"}, 493: {"18": "socket:[6090]", "11": "socket:[9300]", "21": "socket:[9200]"},
            1129: {"1": "socket:[9454]", "2": "socket:[9454]"}}
BASE_PROCS = [SSHD, SSHD_SESSION, NGINX, NETWORKD, SYSTEMD]

ALL = (Prc02, Prc04, Prc06, Prc07, Prc08, Prc09, Net01, Net02)


class TestParse(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual(parse_addr("0100007F:0016", False), ("127.0.0.1", 22))
        self.assertEqual(parse_addr("4510A8C0:0016", False), ("192.168.16.69", 22))
        self.assertEqual(parse_addr("00000000000000000000000001000000:0016", True), ("::1", 22))
        self.assertEqual(parse_addr("0000000000000000FFFF00000100007F:0050", True), ("127.0.0.1", 80))


class NetBase(ProcRootTest):
    def run_checks(self, procs=(), fds=None, extra=None, checks=ALL):
        files = dict(BASE_NET)
        files.update(extra or {})
        root = self.build(BASE_PROCS + list(procs), files)
        all_fds = dict(BASE_FDS)
        all_fds.update(fds or {})
        for pid, table in all_fds.items():
            os.makedirs(os.path.join(root, "proc", str(pid), "fd"), exist_ok=True)
            for fd, target in table.items():
                os.symlink(target, os.path.join(root, "proc", str(pid), "fd", fd))
        ctx = LinkContext(root, NOW)
        out = {}
        for cls in checks:
            c = cls()
            out[cls.id] = (c, c.run(ctx))
        return out


class NetTest(NetBase):
    def test_clean_server(self):
        r = self.run_checks()
        for cid, (c, f) in r.items():
            self.assertEqual(f, [], cid)
        self.assertEqual(r["NET-01"][0].scope, "리스닝 소켓 4개 — tcp/22(sshd), tcp/80(nginx), tcp/2049(커널), "
                                               "udp/68(systemd-networkd), 커널 소켓 1개")
        self.assertEqual(r["PRC-06"][0].scope, "raw·packet 소켓 2개 (네트워크 관리 데몬 1개 제외)")

    def test_reverse_shell(self):
        shell = proc(2000, "bash", 33, 829, "bash -i", "/usr/bin/bash")
        r = self.run_checks([shell], {2000: {"0": "socket:[7777]", "1": "socket:[7777]", "2": "socket:[7777]"}},
                            {"/proc/net/tcp": BASE_NET["/proc/net/tcp"] +
                             inet(9, "4510A8C0:C350", "0500000A:115C", "01", 33, 7777)})  # → 10.0.0.5:4444
        f8 = r["PRC-08"][1]
        self.assertEqual(len(f8), 1)
        self.assertIn("PID 2000 'bash'의 표준 입력·표준 출력·표준 오류가 네트워크 소켓이다 (상대 10.0.0.5:4444)", f8[0].reason)
        f2 = r["NET-02"][1]
        self.assertEqual(len(f2), 1)
        self.assertIn("PID 2000 'bash'가 나가는 연결(상대 10.0.0.5:4444)을 잡고 있다", f2[0].reason)
        self.assertIn("셸(bash)", f2[0].reason)

    def test_nc_listener_and_hidden_owner(self):
        nc = proc(3000, "nc", 1000, 1, "nc -lvp 4444", "/usr/bin/nc.openbsd")
        r = self.run_checks([nc], {3000: {"3": "socket:[8888]"}},
                            {"/proc/net/tcp": BASE_NET["/proc/net/tcp"] +
                             inet(9, "00000000:115C", "00000000:0000", "0A", 1000, 8888) +
                             inet(10, "00000000:7A69", "00000000:0000", "0A", 0, 5555)})  # 31337, 주인 없음
        reasons = [x.reason for x in r["NET-01"][1]]
        self.assertEqual(len(reasons), 2)
        self.assertTrue(any("tcp 0.0.0.0:4444에서 PID 3000 'nc'가 리스닝한다 (네트워크 도구(nc.openbsd))" in x for x in reasons))
        self.assertTrue(any("tcp 0.0.0.0:31337에서 리스닝하는 소켓(inode 5555)이 어느 프로세스의 것도 아니다" in x for x in reasons))

    def test_bind_shell_inbound(self):
        nc = proc(3000, "nc", 1000, 1, "nc -lnv 4444", "/usr/bin/nc.openbsd")
        r = self.run_checks([nc], {3000: {"3": "socket:[8888]", "4": "socket:[8889]"}},
                            {"/proc/net/tcp": BASE_NET["/proc/net/tcp"] +
                             inet(9, "00000000:115C", "00000000:0000", "0A", 1000, 8888) +
                             inet(10, "4510A8C0:115C", "1210A8C0:E5F2", "01", 1000, 8889)},
                            checks=(Net02,))
        f = r["NET-02"][1]
        self.assertEqual(len(f), 1)
        self.assertIn("PID 3000 'nc'가 들어온 연결(4444번 포트 ← 192.168.16.18:58866)을 잡고 있다", f[0].reason)
        self.assertEqual(r["NET-02"][0].title, "의심 프로세스의 외부 연결")

    def test_memfd_by_fd_number(self):
        # /proc/self/fd/3을 실행하면 comm이 '3' (24.04 양성 시험)
        r = self.run_checks([proc(4002, "3", 1000, 1, "sleep 3600", "/memfd:payload (deleted)")], checks=(Prc02,))
        f = r["PRC-02"][1]
        self.assertIn("PID 4002 '3'(명령줄 sleep 3600)가 디스크에 없는 실행 파일(memfd:payload)", f[0].reason)
        self.assertIn("파일 설명자 경로로 실행한 흔적", " ".join(e.detail for e in f[0].evidence))

    def test_memfd(self):
        r = self.run_checks([proc(4000, "x", 0, 1, "x", "/memfd:payload (deleted)"),
                             proc(4001, "runc", 0, 1, "runc init", "/memfd:runc_cloned:/usr/bin/runc (deleted)")],
                            checks=(Prc02, Net01))
        f = r["PRC-02"][1]
        self.assertEqual([(x.severity, x.reason.split(" ")[1]) for x in f], [("critical", "4000"), ("info", "4001")])
        self.assertIn("memfd:payload", f[0].reason)

    def test_kernel_thread_disguise(self):
        r = self.run_checks([proc(5000, "kworker/0:2", 0, 1, "[kworker/0:2]", "/tmp/.x/k"),
                             proc(5001, "watchdog", 0, 1, "/usr/sbin/watchdog", "/usr/sbin/watchdog")], checks=(Prc04,))
        f = r["PRC-04"][1]
        self.assertEqual(len(f), 1)
        self.assertIn("명령줄이 커널 스레드처럼 대괄호로 싸여 있다 ([kworker/0:2])", f[0].reason)
        self.assertIn("이름(comm)이 커널 스레드 꼴이다 (kworker/0:2)", f[0].reason)

    def test_sniffer(self):
        r = self.run_checks([proc(6000, "tcpdump", 0, 1, "tcpdump -i any", "/usr/bin/tcpdump")],
                            {6000: {"3": "socket:[6100]"}},
                            {"/proc/net/packet": BASE_NET["/proc/net/packet"] +
                             "ffff8d7b4452f000 3      3    0003   0     1 0      0      6100\n",
                             "/sys/class/net/enp0s3/flags": "0x1103\n",
                             "/sys/class/net/veth1a/flags": "0x1103\n",
                             "/sys/class/net/lo/flags": "0x9\n"},
                            checks=(Prc06, Net06))
        f6 = r["PRC-06"][1]
        self.assertEqual(len(f6), 1)
        self.assertIn("PID 6000 'tcpdump'", f6[0].reason)  # 패키지 프로그램이라도 수집 도구는 위험
        fn = r["NET-06"][1]
        self.assertEqual(len(fn), 1)
        self.assertIn("인터페이스 enp0s3가 promiscuous", fn[0].reason)
        details = [e.detail for e in fn[0].evidence if "packet 소켓" in e.detail]
        self.assertTrue(details[0].startswith("packet 소켓을 연 프로세스: PID 6000 tcpdump"), details)
        self.assertTrue(details[1].endswith("— 네트워크 관리 데몬"), details)  # systemd-networkd는 뒤로
        self.assertEqual(r["NET-06"][0].scope, "인터페이스 3개, 브리지 포트·veth 1개 제외")

    def test_ld_preload(self):
        r = self.run_checks([proc(7000, "sshd", 0, 1, "sshd: x", "/usr/sbin/sshd")],
                            extra={"/proc/7000/environ": "PATH=/usr/bin\0LD_PRELOAD=/tmp/.l/libh.so\0",
                                   "/tmp/.l/libh.so": "x"}, checks=(Prc07,))
        f = r["PRC-07"][1]
        self.assertEqual(len(f), 1)
        self.assertIn("LD_PRELOAD=/tmp/.l/libh.so", f[0].reason)
        self.assertIn("/tmp/.l/libh.so: 있음, 임시 폴더, 패키지에 속하지 않음", [e.detail for e in f[0].evidence])

    def test_shell_under_kthreadd(self):
        r = self.run_checks([proc(8000, "sh", 0, 2, "/bin/sh -i", "/usr/bin/bash"),
                             proc(8001, "modprobe", 0, 2, "/sbin/modprobe -q -- net-pf-10", "/usr/sbin/modprobe")],
                            checks=(Prc09,))
        f = r["PRC-09"][1]
        self.assertEqual(len(f), 1)
        self.assertIn("PID 8000 'sh'의 부모가 커널 스레드 kthreadd(PID 2)다 (셸·인터프리터)", f[0].reason)
        self.assertIn("PID 2의 사용자 프로세스 2개", r["PRC-09"][0].scope)


# lin.security 정답 (2026-11-06, 복원 상태) — 'rpcinfo' 출력 그대로
RPCINFO_LINSEC = """   program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100005    1    udp       0.0.0.0.155.191        mountd     superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            -          superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100227    3    udp       0.0.0.0.8.1            -          superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 -          superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100227    3    udp6      ::.8.1                 -          superuser
    100021    1    udp       0.0.0.0.216.31         nlockmgr   superuser
    100021    3    udp       0.0.0.0.216.31         nlockmgr   superuser
    100021    4    udp       0.0.0.0.216.31         nlockmgr   superuser
    100021    1    tcp       0.0.0.0.149.119        nlockmgr   superuser
    100021    3    tcp       0.0.0.0.149.119        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.149.119        nlockmgr   superuser
    100021    1    udp6      ::.213.165             nlockmgr   superuser
    100021    3    udp6      ::.213.165             nlockmgr   superuser
    100021    4    udp6      ::.213.165             nlockmgr   superuser
    100021    1    tcp6      ::.135.79              nlockmgr   superuser
    100021    3    tcp6      ::.135.79              nlockmgr   superuser
    100021    4    tcp6      ::.135.79              nlockmgr   superuser
    100021    4    tcp       0.0.0.0.122.105        nlockmgr   unknown
"""
V6 = "00000000000000000000000000000000"


def nfs_files(lockd_ports=(38263, 34639, 55327, 54693), extra_tcp=""):
    """lin.security처럼 주인 프로세스 없는 nfsd(2049)·lockd 소켓. inode는 17425~ (0이 아님)."""
    t, t6, u, u6 = lockd_ports
    return {
        "/proc/net/tcp": BASE_NET["/proc/net/tcp"] + inet(20, "00000000:0801", "00000000:0000", "0A", 0, 17623) +
                         inet(21, "00000000:{:04X}".format(t), "00000000:0000", "0A", 0, 17638) + extra_tcp,
        "/proc/net/tcp6": HEAD + inet(0, V6 + ":0801", V6 + ":0000", "0A", 0, 17635) +
                          inet(1, V6 + ":{:04X}".format(t6), V6 + ":0000", "0A", 0, 17640),
        "/proc/net/udp": BASE_NET["/proc/net/udp"] + inet(20, "00000000:0801", "00000000:0000", "07", 0, 17634) +
                         inet(21, "00000000:{:04X}".format(u), "00000000:0000", "07", 0, 17637),
        "/proc/net/udp6": HEAD + inet(0, V6 + ":0801", V6 + ":0000", "07", 0, 17636) +
                          inet(1, V6 + ":{:04X}".format(u6), V6 + ":0000", "07", 0, 17639),
        "/sys/module/nfsd/refcnt": "2\n",
        "/sys/module/lockd/refcnt": "2\n",
        "/proc/fs/nfsd/portlist": "udp 2049\ntcp 2049\nudp 2049\ntcp 2049\n",
        "/proc/sys/fs/nfs/nlm_tcpport": "0\n",
        "/proc/sys/fs/nfs/nlm_udpport": "0\n",
    }


class TestKernelNfs(NetBase):
    def test_parse_rpcinfo(self):
        info = KernelNfs()
        parse_rpcinfo(RPCINFO_LINSEC, info)
        self.assertEqual(info.ports, {("tcp", 2049): "nfsd", ("udp", 2049): "nfsd", ("tcp6", 2049): "nfsd",
                                      ("udp6", 2049): "nfsd", ("udp", 55327): "lockd", ("tcp", 38263): "lockd",
                                      ("udp6", 54693): "lockd", ("tcp6", 34639): "lockd"})  # mountd·unknown 소유자 제외

    def run_nfs(self, rpc, files, modules=True):
        if not modules:
            files = {k: v for k, v in files.items() if not k.startswith("/sys/module")}

        class N(Net01):
            RPCINFO = staticmethod(lambda: rpc)
        return self.run_checks(extra=files, checks=(N,))["NET-01"]

    def test_linsecurity_baseline(self):
        c, f = self.run_nfs(RPCINFO_LINSEC, nfs_files())
        self.assertEqual(f, [])
        self.assertTrue(c.scope.endswith("커널 소켓 1개, 커널 NFS 소켓 8개"), c.scope)
        self.assertIn("tcp/2049(커널·커널 nfsd)", c.scope)
        self.assertIn("tcp/38263(커널 lockd)", c.scope)

    def test_lockd_port_changes_after_reboot(self):
        # 정답 수집 때 포트(40155 등)와 달라도 portlist·rpcinfo에서 그때그때 읽으므로 맞는다
        rpc = RPCINFO_LINSEC.replace("149.119", "156.219").replace("135.79", "174.93")
        c, f = self.run_nfs(rpc, nfs_files((40155, 44637, 55327, 54693)))
        self.assertEqual(f, [])

    def test_other_unowned_still_flagged(self):
        c, f = self.run_nfs(RPCINFO_LINSEC, nfs_files(
            extra_tcp=inet(22, "00000000:7A69", "00000000:0000", "0A", 0, 5555) +      # 31337 root, 등록 없음
                      inet(23, "00000000:7A6A", "00000000:0000", "0A", 1000, 5556) +   # 31338 일반 계정
                      inet(24, "00000000:7A6B", "00000000:0000", "0A", 0, 5557)))     # 31339 unknown 소유자 등록
        self.assertEqual(sorted((x.severity, x.reason.split(" ")[1]) for x in f),
                         [("warning", "0.0.0.0:31337에서"), ("warning", "0.0.0.0:31338에서"),
                          ("warning", "0.0.0.0:31339에서")])

    def test_nfs_port_held_by_user_is_not_kernel(self):
        files = nfs_files()
        files["/proc/net/tcp"] = files["/proc/net/tcp"].replace(
            inet(20, "00000000:0801", "00000000:0000", "0A", 0, 17623),
            inet(20, "00000000:0801", "00000000:0000", "0A", 1000, 17623))
        c, f = self.run_nfs(RPCINFO_LINSEC, files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("tcp 0.0.0.0:2049", f[0].reason)

    def test_rpcinfo_unavailable(self):
        c, f = self.run_nfs(None, nfs_files())
        self.assertEqual([x.severity for x in f], ["info"] * 4)  # lockd 4개 — nfsd 2049는 portlist로 정상
        self.assertTrue(all("rpcbind 등록을 확인하지 못했다" in x.reason for x in f))
        self.assertIn("커널 NFS 소켓 4개", c.scope)

    def test_without_nfs_modules(self):
        c, f = self.run_nfs(RPCINFO_LINSEC, nfs_files(), modules=False)
        self.assertEqual([x.severity for x in f], ["warning"] * 8)


class FakePrc05(Prc05):
    """kill·ps 결과를 정해 넣는다."""
    alive_set, ps_set, listed_set = set(), set(), set()

    @staticmethod
    def live(ctx):
        return True

    def listing(self, ctx):
        return set(self.listed_set)

    def listing_names(self, ctx):
        return [str(x) for x in self.listed_set]

    @staticmethod
    def pid_max(ctx):
        return 100

    def alive(self, pid_max):
        return set(self.alive_set)

    @staticmethod
    def still_alive(pid):
        return True

    def ps_pids(self):
        return set(self.ps_set)


class TestHiddenProcesses(ProcRootTest):
    def check(self, alive, listed, ps, extra=None):
        root = self.make_root(dict({"/proc/12/status": "Name:\tbash\nTgid:\t12\n",
                                    "/proc/13/status": "Name:\tbash\nTgid:\t12\n"}, **(extra or {})))
        c = FakePrc05()
        c.alive_set, c.listed_set, c.ps_set = alive, listed, ps
        return c, c.run(Context(root, now=NOW))

    def test_clean(self):
        c, f = self.check({1, 2, 12, 13}, {1, 2, 12}, {1, 2, 12})
        self.assertEqual(f, [])  # 13은 12의 스레드
        self.assertEqual(c.scope, "PID 1~100 (/proc 3개, ps 3개)")

    def test_hidden_from_proc_and_ps(self):
        _, f = self.check({1, 2, 12, 66}, {1, 2, 12}, {1, 2},
                          {"/proc/66/status": "Name:\tminer\nTgid:\t66\n", "/proc/66/cmdline": "./miner\0-o\0pool"})
        r = [x.reason for x in f]
        self.assertTrue(any(x.startswith("PID 66는 살아 있는데(kill 응답) /proc 목록에 나오지 않는다") for x in r))
        self.assertTrue(any(x.startswith("PID 12는 /proc에 있는데 ps 결과에 없다") for x in r))

    def test_fake_root_is_skipped(self):
        c = Prc05()
        self.assertEqual(c.run(Context(self.make_root({}), now=NOW)), [])
        self.assertIn("실제 시스템에서만", c.scope)


if __name__ == "__main__":
    unittest.main()
