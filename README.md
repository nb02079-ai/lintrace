# LinTrace

Ubuntu 서버에서 한 번 실행하면 침해 흔적 54개 항목을 점검하고, 판정 근거와 공격 흐름을 담은 한국어 리포트를 내는 진단 도구입니다. KISA 해킹진단도구의 원클릭·신호등 판정 방식을 Linux 서버로 옮기고, 판정마다 근거를 붙이는 쪽으로 확장합니다.

> ⚠️ 본인 소유이거나 점검 권한을 받은 시스템에서만 실행하세요. 이 도구는 시스템을 수정하지 않습니다.

## 상태

1단계(MVP) 완료, 2단계 진행 중 — 구현 37 / 54 (ACC-01~11, PER-01~09, PRC-01~09, FS-02·04·05·06, LOG-01, NET-01·02·06 · `python3 -m lintrace --list`로 확인)

| 단계 | 내용 | 상태 |
| --- | --- | --- |
| 0 | 환경 준비 (정상 VM, 검증용 공개 VM) | 완료 (lin.security, Ubuntu 24.04 + WordPress) |
| 1 | MVP: 항목 10개 + 텍스트 리포트, 검증 VM 적용 | 완료 — [검증 요약](validation/phase1-summary.md): 심어진 경로 6/6 탐지, 실제 웹 서버 오탐 0 |
| 2 | 54개 전 항목, JSON 결과, 증거 아카이브 | 진행 중 — 2-0(JSON·증거 아카이브), 2-A(계정·인증 8개), 2-B(프로세스·네트워크 10개), 2-C(지속성·패키지 무결성 9개) 구현 |
| 3 | 타임라인 상관분석, ATT&CK 매핑, 기준선 비교, HTML 리포트 | 예정 |
| 4 | 종합 검증, 기존 도구 비교, 결과 공개 | 예정 |

## 대상

- Ubuntu Server 22.04 / 24.04 LTS, 웹 서버 1대 (SSH + Nginx/Apache)
- Python 3.6 이상, 표준 라이브러리만 사용 (Ubuntu 18.04 기본 버전까지 지원)

## 실행

```bash
sudo python3 -m lintrace            # 점검 실행
sudo python3 -m lintrace --json result.json     # 같은 결과를 JSON으로도 저장 ('-'면 화면에 JSON만)
sudo python3 -m lintrace --out /mnt/usb/case1   # 증거 아카이브 (근거 파일 복사본, 해시 목록, tar.gz)
sudo python3 -m lintrace --full                 # 패키지 무결성(FS-04)을 모든 패키지 파일로 (기본은 핵심 경로, 느림)
python3 -m lintrace --list          # 점검 항목과 구현 상태
python3 -m unittest discover -s tests   # 테스트
```

파일 변경 시각은 `touch`로 조작할 수 있어 위험도 판단에 쓰지 않고, 근거에 경과 시간(예: `3일 전 (2026-10-30 14:02:11 +0900)`)으로만 표시합니다. 미래 시각만 조작 흔적으로 봅니다.

root가 아니면 읽지 못하는 파일이 있어 해당 항목은 리포트에 **점검 불가**로 따로 표시됩니다. 점검 불가 항목은 "이상 없음"으로 세지 않습니다.

`/etc/ld.so.preload`에 라이브러리가 적혀 있으면 판정 줄 바로 아래에 **결과 신뢰 경고**를 붙입니다. 도구 자신의 `/proc/self/maps`로 그 라이브러리가 실제로 불려 들어갔는지 확인해, 불려 들어갔다면 루트킷이 결과를 숨겼을 수 있다고 알립니다.

리포트 끝의 **점검 범위** 구역에 모든 항목이 무엇을 확인했고 결과가 어땠는지 모아서 보여줍니다. 볼 게 없었던 것과 보고도 못 찾은 것을 구분하고, 몇 개를 보고 몇 개를 찾았는지(오탐 수준)를 함께 판단하기 위해서입니다.

```
점검 범위:
  ACC-07 — 키 파일 1개, 키 0개 확인 (이상 없음)
  PER-01 — 예약 작업 7개, root가 실행하는 스크립트 16개 확인 (탐지 1건)
```

테스트는 root와 일반 계정 양쪽에서 돌려야 전부 실행됩니다. 파일 소유자를 root로 맞춰야 하는 테스트는 일반 계정에서, 권한 없는 파일을 다루는 테스트는 root에서 건너뜁니다.

**JSON 결과**(schema 1)에는 도구 버전과 코드 지문(`code_sha256`), 실행 환경, 항목마다 상태(`detected`/`clean`/`unavailable`)·확인 범위·탐지 근거가 들어갑니다. 탐지가 없는 항목도 모두 넣습니다.

**증거 아카이브**는 탐지 근거가 된 파일을 원래 경로 구조 그대로 읽기 전용으로 복사하고, 원래 크기·권한·소유자·시각·inode·SHA-256을 `manifest.json`에 남깁니다. 프로세스가 붙잡고 있는 지워진 파일(`/proc/PID/fd/N`, `/proc/PID/exe`)도 복사하므로, `sed -i`로 줄을 지운 로그의 원래 내용이나 지워진 실행 파일을 재시작 전에 보존할 수 있습니다. 원본을 그대로 복사하므로 비밀 정보가 들어 있을 수 있어 폴더는 0700으로 만듭니다. 파일당 50MB·전체 500MB를 넘으면 복사하지 않고 해시만 남깁니다. 점검 대상은 바꾸지 않고, `--out`으로 지정한 곳에만 씁니다.

## 구조

```
lintrace/
  checks/        점검 항목 (항목 하나 = 파일 하나, base.py가 공통 틀)
  collectors/    여러 항목이 공유하는 수집기 — processes(프로세스·열린 파일), accounts(passwd·shadow·group),
                 authlog(auth.log·순환·gz, 18.04·24.04 형식), packages(dpkg 소속·md5sums, usrmerge 별칭),
                 sockets(/proc/net의 tcp·udp·raw·packet·unix + 소켓을 잡은 프로세스),
                 nfs(커널 nfsd·lockd 소켓 포트 — portlist·nlm 포트·rpcbind 등록)
  checks/scriptscan.py  스크립트·명령의 의심 패턴 (PER-01·03·04·06·08·09 공용)
  checks/persist.py     패키지 원본 비교·소유자·실행 대상 판정 (2-C 공용)
  report/        리포트 출력 (1단계 텍스트 → 3단계 HTML)
rules/catalog.json   54개 항목 목록 (ID, 위험도, ATT&CK, 구현 단계)
tests/           항목별 단위 테스트와 가짜 파일시스템 fixture
validation/      검증 VM 기록, 시나리오, 측정 결과
docs/            설계 문서
```

## 점검 항목 추가하는 법

1. `rules/catalog.json`에서 항목 ID를 확인한다.
2. `lintrace/checks/acc_01.py`를 본떠 `<id>.py`를 만든다. 파일은 반드시 `ctx.read_lines()` / `ctx.list_dir()`로 읽는다. 읽지 못하면 이 함수들이 `Unavailable`을 내서 '점검 불가'로 처리되므로, 직접 `open()`하고 예외를 삼키지 않는다.
3. `lintrace/checks/__init__.py`의 `ALL_CHECKS`에 등록하고, `rules/catalog.json`의 `status`를 `implemented`로 바꾼다 (`tests/test_runner.py`가 이름·위험도·ATT&CK 일치를 확인한다).
4. `tests/helpers.py`의 `make_root()`로 걸리는 경우와 깨끗한 경우를 만들어 테스트를 작성한다.
5. Python 3.6 호환을 지킨다 (dataclasses, `X | None`, `list[...]` 표기 금지).
6. 변경 시각은 위험도 조건에 쓰지 않는다. 근거에 `timefmt.describe(st.st_mtime, ctx.now)`로 표시만 한다.
7. `run()` 끝에 `self.scope`로 확인 범위를 남긴다 (예: `"키 파일 {}개, 키 {}개"`). 결과 전체의 신뢰도에 관한 사실은 `self.report_warnings`에 문장으로 남긴다.
8. 프로세스 정보는 `/proc`를 직접 훑지 말고 `collectors.processes.processes(ctx)`를 쓴다. 항목마다 따로 읽으면 그사이 프로세스가 생기거나 끝나 결과가 엇갈린다.
9. 파일 존재 확인은 `os.path.exists()` 대신 `ctx.stat()`을 쓴다. 상위 디렉터리 권한이 없을 때 "없음"과 "못 봄"을 구분하기 위해서다. (`ctx.read_lines()`는 FIFO 등 일반 파일이 아닌 것을 열지 않는다.)

## 검증

공개 취약 VM(lin.security)과 실제 웹 서버로 구성한 Ubuntu 24.04 VM(nginx + WordPress, 침투 시나리오 재현용)에 적용해 탐지율·오탐률을 측정합니다. 방법과 결과는 [validation/](validation/README.md)에 기록합니다.

## 문서

- [프로젝트 개요](docs/overview.md)
