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

## 2차 적용

(대기) 기대: FS-06 탐지 0건, 다른 항목 1차와 같음
