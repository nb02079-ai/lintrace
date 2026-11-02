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

## 검증자 활동 (auth.log에 남는 기록)

탐지 결과와 섞이지 않도록 따로 적는다.

1. `sudo python3 -m lintrace` — 거부 (2회)
2. `sudo -l` — 1회
3. `sudo /bin/bash -c 'cd /home/bob/lintrace && python3 -m lintrace'` — 1회
