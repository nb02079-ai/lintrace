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
