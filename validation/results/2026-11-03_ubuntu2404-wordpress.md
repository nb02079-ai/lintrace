# 2026-11-03 Ubuntu 24.04 + nginx + WordPress 기준선

- VM: Ubuntu 24.04 (직접 설치), nginx + php-fpm 8.3 + MariaDB + WordPress 최신판, 스냅샷 `web-baseline`
- 웹 설정: nginx `root /var/www/wordpress`, 기본 사이트 제거, 관리자 화면에서 이미지 1장 업로드
- 실행 계정: `test` (sudo 그룹), `sudo python3 -m lintrace`
- 목적: 아무것도 심지 않은 실제 웹 서버에서 전체 항목의 오탐 측정, 이후 WordPress 구조에 웹쉘을 심어 FS-06 양성 확인

## 도구 복사 중 발견한 문제

| 발견 | 원인 | 조치 |
| --- | --- | --- |
| `SyntaxError: source code string cannot contain null bytes` | 첫 복사가 디스크에 다 써지기 전에 끊겨 파일 일부가 0으로 채워짐 | 지우고 다시 복사, 복사 뒤 `sync` |
| 커밋은 같은데 코드 해시가 다름, `git status`에 38개 수정 | 호스트(Windows) git의 `core.autocrlf`로 줄바꿈이 CRLF로 바뀜 | VM에서 `git checkout -- .`, 호스트에 `core.autocrlf input` |
| (2차) 복사본의 `.git` 손상, 커밋이 이전 버전에 머묾 | 호스트 쪽 손상 추정 | 새로 clone한 폴더를 `tar`로 묶어 한 파일로 전송 |
| (2차) 새로 받은 폴더에서 `tests/test_fs_06.py`만 사라짐 | 웹쉘 테스트 문자열이 든 파일이라 Windows 백신 격리로 추정 (보호 기록 확인 대기) | VM에서 `git checkout -- .`로 복구 후 해시 확인 |

코드 동일성은 커밋이 아니라 파일 해시로 확인한다:
`find lintrace tests rules -type f \( -name '*.py' -o -name '*.json' \) | LC_ALL=C sort | xargs sha256sum | sha256sum`

## 1차 적용 (커밋 9a5a74d, 코드 1f0c0fc)

| 항목 | 점검 범위 | 결과 |
| --- | --- | --- |
| ACC-01 | 계정 36개 | 이상 없음 |
| ACC-06 | sudoers 파일 2개, 사용자 규칙 3개 | 이상 없음 (`%sudo` 기본 규칙 제외) |
| ACC-07 | 키 파일 2개, 키 0개 | 이상 없음 |
| PER-01 | 예약 작업 9개, root가 실행하는 스크립트 10개 | 이상 없음 |
| PER-05 | preload 없음, 라이브러리 경로 4개 | 이상 없음 |
| PRC-01·PRC-03 | 프로세스 107개 | 이상 없음 |
| FS-02 | 파일 85,132개 중 SUID·SGID 21개 (패키지 소속 21개) | 이상 없음 |
| FS-06 | 웹 루트 1개 (/var/www), 스크립트·이미지 파일 1,738개 | **오탐 39건** |

정답 자료(`truth.txt`) 대조는 대기.

### FS-06 오탐 원인

WordPress GitHub 미러(2026-11-03 trunk)로 재현: 파일 2,459개 중 44건 (VM과 버전·테마 수 차이).

| 원인 | 건수 | 예 |
| --- | --- | --- |
| 백틱 규칙이 문서 주석의 마크다운 표기와 문자열 속 SQL 백틱까지 셸 실행으로 봄 | 심각 34 | `pluggable.php` `` Key to check for nonce in `$_REQUEST` ``, `class-wpdb.php` `` 'WHERE `%1$s` = "%2$s"', $_GET['key'] `` |
| 이미지 속 PHP를 `<?=` 3바이트로 판정 — PNG 압축 데이터에서 우연히 나옴 | 심각 4 | 테마 `screenshot.png` (`<?=\x9b\xcf…`) |
| 업로드 폴더 이름에 `files`·`image` 등이 있고 대소문자 무시 | 위험 6 | `php-ai-client/src/Files/`, `block-library/image/` |

### 수정 (커밋은 아래 2차 적용 참고)

1. PHP 파일은 코드 부분만 검사: 태그 밖 HTML과 주석을 공백으로 지움 (줄 번호 유지). 문자열·heredoc은 건너뛰며 읽고 `#[...]`(PHP 8 속성)은 주석으로 보지 않음
2. 백틱 규칙은 문자열 밖의 실제 백틱 구간 안에 요청 값이 있을 때만
3. 이미지 속 PHP는 `<?php` + 공백·괄호, 또는 `<?=` + `$`·`@`·`(`
4. 업로드 폴더 이름은 `uploads`·`upload`·`user_files`·`attachments`, 소문자 그대로 비교
5. 요청 값·디코딩 함수·`preg_replace`가 없는 파일은 해석을 건너뜀 (속도)

수정 후 같은 WordPress 트리: 2,459개 중 0건, 3.4초 (수정 전 44건, 3.5초).
WordPress 구조에 심은 웹쉘 3개(업로드 폴더 `s.php`, 업로드 폴더 `p.jpg`, 플러그인 폴더 백틱 실행) 모두 심각.
회귀 테스트: 위 세 원인을 본뜬 WordPress 코어 모양 파일, 주석 뒤에 숨긴 웹쉘, HTML 속 `` <?= `$_GET[c]` ?> ``, heredoc 뒤 `assert($_POST)`.

## 2차 적용 (커밋 67e9e26, 코드 해시 fa7660a7…d52289a1)

- 단위 테스트 (Python 3.12): 132개 통과 — 일반 계정 27개, root 6개 건너뜀

| 항목 | 점검 범위 | 결과 |
| --- | --- | --- |
| 전체 판정 | 실행 9개, 탐지 0건, 점검 불가 0개 | **정상** |
| ACC-01 | 계정 36개 | 이상 없음 |
| ACC-06 | sudoers 파일 2개, 사용자 규칙 3개 | 이상 없음 |
| ACC-07 | 키 파일 2개, 키 0개 | 이상 없음 |
| PER-01 | 예약 작업 9개, 스크립트 10개 | 이상 없음 |
| PER-05 | preload 없음, 라이브러리 경로 4개 | 이상 없음 |
| PRC-01·PRC-03 | 프로세스 106개 | 이상 없음 |
| FS-02 | 파일 85,054개 중 SUID·SGID 21개 (패키지 소속 21개) | 이상 없음 |
| FS-06 | 웹 루트 1개 (/var/www), 스크립트·이미지 파일 1,738개 | 이상 없음 (1차 39건 → 0건) |

실제 웹 서버(nginx + php-fpm + MariaDB + WordPress)에서 9개 항목 오탐 0. 정답 자료(`truth.txt`) 대조는 대기.

## 3차 적용 — FS-06 양성 확인 (WordPress 구조에 웹쉘 심기)

`www-data`로 업로드 폴더·가짜 플러그인·코어 폴더 위장 파일을 만들고, 정상 테마 `functions.php` 끝에 한 줄을 덧붙인 뒤 실행.

| 파일 | 기대 | 결과 |
| --- | --- | --- |
| `wp-content/uploads/2026/11/cache.php` (`@eval($_POST[..])`) | 심각 (요청 값 → 실행; 업로드 폴더) | 일치 |
| `wp-content/uploads/2026/11/avatar.jpg` (GIF 헤더 + PHP) | 심각 (이미지 속 PHP) | 일치 |
| `wp-content/plugins/hello-x/hello-x.php` (백틱 실행) | 심각, 근거 5행 | 일치, 근거 5행 `` echo `{$_REQUEST["k"]}`; `` |
| `wp-includes/class-wp-cache-helper.php` (`eval(gzinflate(base64_decode(..)))`) | 심각 (인코딩 풀어 실행) | 일치 |
| `wp-content/themes/twentytwentyfive/functions.php` 끝에 `$_GET["f"]($_GET["c"]);` | 심각 | 일치, 근거 160행 (정상 코드 159줄 뒤에 끼운 한 줄을 찾음) |
| `wp-content/uploads/2026/11/info.php` (`phpinfo()`) | 위험 (업로드 폴더 안 스크립트) | 일치 |
| `wp-content/uploads/2026/11/index.php` (Silence is golden) | 탐지 없음 | 일치 |
| 점검 범위 "스크립트·이미지 파일 1744개" (1,738 + 새 파일 6) | | 일치 |
| 다른 8개 항목 | 변화 없음 | 일치 |

FS-06 탐지 6건 (심각 5, 위험 1). 이후 `web-baseline` 스냅샷 복원.

## 정답 자료 대조 (`truth.txt`, 3차 적용 직후 같은 상태에서 수집)

| 항목 | 정답 자료 | 도구 점검 범위 | 대조 |
| --- | --- | --- | --- |
| ACC-01 | UID 0은 `root`만 | 계정 36개, 이상 없음 | 일치 |
| ACC-06 | 규칙 `root`, `%admin`, `%sudo` 3개 (모두 기본 관리자 규칙), `@includedir /etc/sudoers.d` | sudoers 파일 2개, 사용자 규칙 3개, 이상 없음 | 일치 |
| ACC-07 | `/home/test/.ssh/authorized_keys`, `/root/.ssh/authorized_keys` — 둘 다 0바이트, 600, 소유자 본인. 그 밖에 man 페이지 심볼릭 링크 1개 | 키 파일 2개, 키 0개, 이상 없음 | 일치 (man 페이지 링크는 키 파일이 아니라 제외) |
| PER-01 | `/etc/crontab` run-parts 4줄, `cron.d`의 `e2scrub_all`·`php`·`sysstat`, 사용자 crontab 없음 | 예약 작업 9개, 이상 없음 | 탐지 없음 일치 (9개는 cron.d 파일 안 여러 줄 포함) |
| PER-05 | `/etc/ld.so.preload` 없음 | preload 없음, 이상 없음 | 일치 |
| PRC-01·PRC-03 | 지워진 실행 파일·임시 폴더 실행 프로세스 없음 | 프로세스 107개, 이상 없음 | 일치 |
| FS-02 | SUID·SGID 21개: `chage` `chfn` `chsh` `crontab` `expiry` `fusermount3` `gpasswd` `mount` `newgrp` `passwd` `ssh-agent` `su` `sudo` `umount` `dbus-daemon-launch-helper` `auth_pam_tool`(MariaDB) `ssh-keysign` `polkit-agent-helper-1` `utempter` `pam_extrausers_chkpwd` `unix_chkpwd` | SUID·SGID 21개 (패키지 소속 21개), 이상 없음 | 일치 — 셸 탈출 프로그램 없음, MariaDB 설치로 생긴 `auth_pam_tool`도 패키지 소속으로 정상 처리 |

Ubuntu 24.04 + WordPress 검증 정리: 아무것도 심지 않은 상태에서 9개 항목 오탐 0 (FS-06 수정 후), 웹쉘 양성 확인 7개 모두 일치. 이후 `web-baseline` 복원.

## LOG-01 정답 (2026-11-03, `web-baseline` 상태)

- rsyslog 설정이 기록하는 파일 7개: `auth.log`, `syslog`(`-` 비동기), `kern.log`(`-`), `mail.log`(`-`), `mail.err`, `ufw.log`(`:msg,contains` 필터), `cloud-init.log`(`:syslogtag` 필터). `$IncludeConfig /etc/rsyslog.d/*.conf`
- 실제 있는 파일: `auth.log` 16,547B, `syslog` 461,644B, `kern.log` 229,724B. `mail.*`은 없음 (메시지가 올 때 rsyslog가 만듦 — 정상)
- 순환 파일 없음 (설치 직후라 `.1` 없음)
- 웹 로그: `/var/log/nginx/access.log` 58,258B, `error.log` 969B. Apache 없음
- 로그를 연 프로세스: rsyslogd(674) — syslog·kern.log·auth.log / nginx(766·767) — access.log·error.log / php-fpm(634) — `php8.3-fpm.log` / systemd-journald(285) — `system.journal`·`user-1000.journal` / unattended-upgrades(705)
- 지워진 채 열린 로그: 없음
- `auth.log`·`syslog` 첫 글자: `2026-11-03T01:37:19.443184+00:00` (24.04 형식, NUL 없음)
- 기대: LOG-01 탐지 없음

설계에 반영할 관찰:
- 설정에 있지만 아직 없는 파일(`mail.*` 등)은 정상 → 탐지하지 않고 점검 범위에 개수만
- 필터 줄(`:msg,contains,…`)과 비동기 표시(`-/var/log/…`)도 대상 경로로 읽어야 함
- rsyslog·nginx 말고도 php-fpm·journald·unattended-upgrades가 `/var/log` 파일을 엶 — 지워진 채 열린 검사는 기록 프로세스 전체에 적용, journal(`/var/log/journal/`)은 LOG-04·05 영역이라 제외

## 4차 적용 — LOG-01 (커밋 4ace10c, 코드 해시 6315b457…)

- 단위 테스트 151개 통과 (root 6개 건너뜀), 실행한 점검 10개, 전체 판정 정상
- LOG-01 탐지 없음: "rsyslog 대상 7개, 웹 로그 2개, 그중 있는 파일 6개 (나머지 3개는 아직 만들어지지 않음), 로그를 연 프로세스 6개" (정답 때 5개 → 그사이 설정 파일 하나가 새로 생김)

양성 확인: `sudo sed -i '/GET/d' /var/log/nginx/access.log`

| 기대 | 결과 |
| --- | --- |
| LOG-01 심각, nginx 프로세스 2개 | 일치 — master(PID 743, root)·worker(PID 745, www-data) 모두 fd 4로 지워진 원래 파일을 붙잡음 |
| 원래·지금 크기 비교 | 원래 inode 134774·58,258B → 지금 inode 139920·6,517B (GET 요청 줄 삭제분 51,741B) |
| 다른 9개 항목 변화 없음 | 일치 |

이후 `web-baseline` 복원.

## 5차 적용 — 2-0 JSON·증거 아카이브 (커밋 2028e04, 버전 0.1.0, 코드 해시 1df9a40f…)

`web-baseline` 복원 후 복사. 단위 테스트 158개 통과.

| 확인 | 결과 |
| --- | --- |
| 기준선 `--json --out` | 전체 판정 정상, 10개 항목 이상 없음. JSON `verdict: clean`, counts 모두 0, `code_sha256` 일치 |
| 아카이브 | 근거 경로 0개 — 탐지가 없으면 리포트·manifest·해시 목록만 담김 |

양성 확인: `sudo sed -i '/GET/d' /var/log/nginx/access.log` 후 `--out`

| 확인 | 결과 |
| --- | --- |
| LOG-01 | 심각 (nginx가 지워진 access.log를 붙잡음) |
| 아카이브 | 근거 경로 4개 중 2개 복사 (`/proc/<PID>` 폴더 2개는 복사 대상 아님) |
| 지운 줄 복구 | 현재 access.log의 `GET` 0줄 → 아카이브 `evidence/proc/814/fd/4`에 182줄 |

이후 `web-baseline` 복원.

## 2-A 계정·인증 정답 (2026-11-05, `web-baseline`)

- ACC-02: 계정 파일 불일치 없음
- ACC-03: `sync`뿐 → 제외 대상
- ACC-04: 이상 없음
- ACC-05: `adm`에 syslog·test, `sudo`에 test, `lxd`에 test (설치 프로그램이 첫 계정에 기본으로 넣음). `root`·`disk`·`shadow` 구성원 없음
- ACC-08/09: auth.log에서 sshd 성공·실패 기록을 찾지 못함 — PuTTY로 접속했는데 없음, 확인 필요
- ACC-10: 기본값 (`Include /etc/ssh/sshd_config.d/*.conf`, `KbdInteractiveAuthentication no`, `UsePAM yes` 등), 위험 설정 없음
- ACC-11: `pam_permit.so`는 Ubuntu 기본 위치에만. 정답 수집 스크립트가 `/lib/x86_64-linux-gnu/security/*.so` 전부를 "패키지 밖"으로 냈으나 이는 스크립트 문제 — usrmerge 시스템에서 dpkg는 `/usr/lib/...`로 적어 두는데 `/lib/...` 경로로 물었기 때문 (`/usr/lib/...` 쪽은 모두 패키지 소속). 도구의 패키지 DB는 FS-02처럼 usrmerge 별칭을 맞춰야 함

기대: 2-A 8개 항목 모두 탐지 없음. ACC-05 점검 범위에 test의 관리자 그룹(sudo·lxd) 목록.

### auth.log 중간의 NUL 구간 (2026-11-05 확인)

- `/var/log/auth.log` 165줄 중 10·18·95행에 NUL 바이트, 합계 3,077바이트. 파일 앞부분이 아니라 중간 세 곳
- 이 때문에 `grep`이 파일을 바이너리로 보고 줄을 출력하지 않아, 2-A 정답 수집에서 sshd 기록이 "없음"으로 보였음. `grep -a`로 보면 기록이 있음: `sshd[1300]: Accepted password for test from 192.168.16.18 port 61667 ssh2` (24.04도 프로그램 이름은 `sshd`)
- 원인 추정: 기록 중이던 auth.log가 스냅샷에 담긴 뒤 복원 — 파일 크기는 늘었는데 데이터 블록은 비어 있던 부분이 0으로 남고, 그 뒤로 rsyslog가 이어 씀. `web-baseline` 복원 횟수와 NUL 구간 수(3곳)가 맞음
- journal에도 같은 sshd 기록이 있음 (`journalctl -u ssh`) — 2-E에서 사용

도구 설계 반영: 인증 로그 해석기는 NUL을 건너뛰고 끝까지 읽는다. LOG-01은 앞부분 NUL만 보므로 이 상태는 탐지하지 않는다 (중간 NUL 처리는 결정 대기).
