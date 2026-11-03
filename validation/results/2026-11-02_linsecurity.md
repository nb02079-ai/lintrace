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
