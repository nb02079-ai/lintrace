# 검증

## VM

| VM | 기반 | 쓰임 | 출처 | 해시 확인 |
| --- | --- | --- | --- | --- |
| lin.security | Ubuntu 18.04 | 설정 흔적 탐지 (ACC·FS) | https://vulnhub.com/entry/linsecurity-1,244/ | |
| Metasploitable3 ub1404 | Ubuntu 14.04 | 웹 침투 재현 후 FS·CMD·NET | https://github.com/rapid7/metasploitable3 | |
| 깨끗한 Ubuntu | 24.04 | 기준선, 오탐 측정, 시나리오 재현. nginx·php-fpm·WordPress를 설치해 실제 웹 서버 환경의 전체 항목 오탐 기준선과 FS-06 검증(웹 루트 찾기, 정상 코드 오탐, 업로드 폴더에 심은 웹쉘)에 씀 | 직접 설치 | |

24.04에서 미리 알아둘 차이: auth.log 시각이 `2026-11-02T15:32:10.123456+09:00` 형식이고(18.04는 `Nov  2 15:32:10`), SSH는 `ssh.socket`이 포트를 연다. 로그를 읽는 항목과 리스닝 포트·systemd 기준선은 두 경우를 모두 고려한다.

VM에 도구를 복사하는 방법 (호스트가 Windows일 때):

1. 호스트: 커밋마다 새 폴더로 clone — `git clone -c core.autocrlf=input <저장소> lt-<커밋>`
2. 호스트: `tar czf lintrace.tgz --exclude "*test_fs_06.py" -C lt-<커밋> .` — 웹쉘 테스트 문자열이 든 `tests/test_fs_06.py`는 Windows 백신이 읽기를 막아, 넣으면 묶음이 그 지점부터 깨진다
3. 호스트: `certutil -hashfile lintrace.tgz SHA256` → `scp`
4. VM: `sha256sum`으로 전송 확인 → `tar tzf ~/lintrace.tgz > /dev/null`로 묶음 검사 → 풀기 → `sync`
5. VM: `git checkout -- .` (빠진 `test_fs_06.py`를 저장소 기록에서 복구) → 코드 해시 확인

같은 코드인지는 커밋이 아니라 파일 해시로 확인한다 (results/2026-11-03_ubuntu2404-wordpress.md).

모든 VM은 호스트 전용 네트워크에서만 실행한다. 공개 VM은 버전이 달라 경로·로그 포맷 차이로 생긴 미탐은 따로 표시한다.

## 결과 요약

- [1단계 검증 요약](phase1-summary.md) — lin.security 심어진 경로 6/6 탐지, Ubuntu 24.04 + WordPress 오탐 0

## 기록 방법

- `scenarios/` — 재현 시나리오 하나당 파일 하나 (재현 절차, 걸려야 할 항목)
- `results/` — 실행 날짜별 결과 (`YYYY-MM-DD_<vm>.md`): 도구 버전, 걸린 항목, 걸려야 했는데 안 걸린 항목과 이유

## 측정 지표

- 탐지율: 걸려야 할 항목 중 실제로 걸린 비율
- 오탐률: 깨끗한 VM에서 걸린 항목 수
- 판정 정확도: 최종 판정이 기대값과 맞는지
