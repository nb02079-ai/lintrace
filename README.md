# LinTrace

Ubuntu 서버에서 한 번 실행하면 침해 흔적 52개 항목을 점검하고, 판정 근거와 공격 흐름을 담은 한국어 리포트를 내는 진단 도구입니다. KISA 해킹진단도구의 원클릭·신호등 판정 방식을 Linux 서버로 옮기고, 판정마다 근거를 붙이는 쪽으로 확장합니다.

> ⚠️ 본인 소유이거나 점검 권한을 받은 시스템에서만 실행하세요. 이 도구는 시스템을 수정하지 않습니다.

## 상태

1단계(MVP) 진행 중 — 구현 1 / 52 (`python3 -m lintrace --list`로 확인)

| 단계 | 내용 | 상태 |
| --- | --- | --- |
| 0 | 환경 준비 (정상 VM, 검증용 공개 VM) | 예정 |
| 1 | MVP: 항목 10개 + 텍스트 리포트, lin.security 첫 적용 | 진행 중 |
| 2 | 52개 전 항목, JSON 결과, 증거 아카이브 | 예정 |
| 3 | 타임라인 상관분석, ATT&CK 매핑, 기준선 비교, HTML 리포트 | 예정 |
| 4 | 종합 검증, 기존 도구 비교, 결과 공개 | 예정 |

## 대상

- Ubuntu Server 22.04 / 24.04 LTS, 웹 서버 1대 (SSH + Nginx/Apache)
- Python 3.10 이상, 표준 라이브러리만 사용

## 실행

```bash
sudo python3 -m lintrace            # 점검 실행
python3 -m lintrace --list          # 점검 항목과 구현 상태
python3 -m unittest discover -s tests   # 테스트
```

## 구조

```
lintrace/
  checks/        점검 항목 (항목 하나 = 파일 하나, base.py가 공통 틀)
  collectors/    여러 항목이 공유하는 수집기 (2단계부터)
  report/        리포트 출력 (1단계 텍스트 → 3단계 HTML)
rules/catalog.json   52개 항목 목록 (ID, 위험도, ATT&CK, 구현 단계)
tests/           항목별 단위 테스트와 가짜 파일시스템 fixture
validation/      검증 VM 기록, 시나리오, 측정 결과
docs/            설계 문서
```

## 점검 항목 추가하는 법

1. `rules/catalog.json`에서 항목 ID를 확인한다.
2. `lintrace/checks/acc_01.py`를 본떠 `<id>.py`를 만든다. 파일 경로는 반드시 `ctx.path()` / `ctx.read_lines()`로 읽는다.
3. `lintrace/checks/__init__.py`의 `ALL_CHECKS`에 등록한다.
4. `tests/fixtures/`에 걸리는 경우와 깨끗한 경우를 만들고 테스트를 작성한다.

## 검증

공개 취약 VM(lin.security, Metasploitable3)과 깨끗한 Ubuntu VM에 적용해 탐지율·오탐률을 측정합니다. 방법과 결과는 [validation/](validation/README.md)에 기록합니다.

## 문서

- [프로젝트 개요](docs/overview.md)
