# 검증

## VM

| VM | 기반 | 쓰임 | 출처 | 해시 확인 |
| --- | --- | --- | --- | --- |
| lin.security | Ubuntu 18.04 | 설정 흔적 탐지 (ACC·FS) | https://vulnhub.com/entry/linsecurity-1,244/ | |
| Metasploitable3 ub1404 | Ubuntu 14.04 | 웹 침투 재현 후 FS·CMD·NET | https://github.com/rapid7/metasploitable3 | |
| 깨끗한 Ubuntu | 22.04 / 24.04 | 기준선, 오탐 측정, 시나리오 재현 | 직접 설치 | |

모든 VM은 호스트 전용 네트워크에서만 실행한다. 공개 VM은 버전이 달라 경로·로그 포맷 차이로 생긴 미탐은 따로 표시한다.

## 기록 방법

- `scenarios/` — 재현 시나리오 하나당 파일 하나 (재현 절차, 걸려야 할 항목)
- `results/` — 실행 날짜별 결과 (`YYYY-MM-DD_<vm>.md`): 도구 버전, 걸린 항목, 걸려야 했는데 안 걸린 항목과 이유

## 측정 지표

- 탐지율: 걸려야 할 항목 중 실제로 걸린 비율
- 오탐률: 깨끗한 VM에서 걸린 항목 수
- 판정 정확도: 최종 판정이 기대값과 맞는지
