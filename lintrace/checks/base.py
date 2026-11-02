"""점검 항목의 공통 틀.

모든 점검 항목은 Check를 상속하고 run()에서 Finding 목록을 돌려준다.
파일 경로는 항상 ctx.path()로 만든다. 그래야 테스트에서 가짜 루트(fixture)를
가리켜 실제 시스템 없이 점검 로직을 검증할 수 있다.

Python 3.6 호환을 유지한다 (Ubuntu 18.04 기본 버전).
dataclasses, `from __future__ import annotations`, `X | None`, `list[...]` 표기는 쓰지 않는다.
"""
import os
import stat
import time
from typing import List, Optional


class Evidence:
    """판정 근거가 된 원본 증거 한 건."""

    def __init__(self, source: str, detail: str, sha256: Optional[str] = None):
        self.source = source      # 파일 경로나 명령 이름
        self.detail = detail      # 해당 줄, 값 등
        self.sha256 = sha256

    def to_dict(self) -> dict:
        return {"source": self.source, "detail": self.detail, "sha256": self.sha256}

    def __eq__(self, other):
        return isinstance(other, Evidence) and self.to_dict() == other.to_dict()

    def __repr__(self):
        return "Evidence({!r}, {!r}, sha256={!r})".format(self.source, self.detail, self.sha256)


class Finding:
    def __init__(self, check_id: str, title: str, severity: str, attack: str,
                 reason: str, next_steps: str,
                 evidence: Optional[List[Evidence]] = None,
                 timestamp: Optional[float] = None):
        self.check_id = check_id
        self.title = title
        self.severity = severity      # critical / warning / info
        self.attack = attack
        self.reason = reason          # 왜 의심스러운지
        self.next_steps = next_steps  # 다음에 확인할 것
        # 기본값을 None으로 받아 매번 새 리스트를 만든다 (가변 기본값 공유 방지)
        self.evidence = list(evidence) if evidence is not None else []
        self.timestamp = timestamp    # 상관분석용 (알 수 있을 때만)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id, "title": self.title, "severity": self.severity,
            "attack": self.attack, "reason": self.reason, "next_steps": self.next_steps,
            "evidence": [e.to_dict() for e in self.evidence], "timestamp": self.timestamp,
        }

    def __eq__(self, other):
        return isinstance(other, Finding) and self.to_dict() == other.to_dict()

    def __repr__(self):
        return "Finding({} {!r})".format(self.check_id, self.reason)


class Unavailable(Exception):
    """점검을 끝까지 하지 못했음을 알린다 (권한 없음, 필수 파일 없음 등).

    점검 항목에서 이 예외가 나오면 그 항목은 '이상 없음'이 아니라 '점검 불가'로
    리포트된다. 읽지 못한 것을 정상으로 보고하는 일을 막기 위한 장치다.
    """


class Context:
    """점검 실행 환경. root는 기본 '/'이고 테스트에서는 fixture 디렉터리."""

    def __init__(self, root: str = "/", now: Optional[float] = None):
        self.root = root
        # 점검 기준 시각. 테스트에서 고정할 수 있게 주입받는다.
        self.now = time.time() if now is None else now

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def exists(self, p: str) -> bool:
        return os.path.lexists(self.path(p))

    def stat(self, p: str, follow: bool = False):
        """파일 정보를 돌려준다. 없으면 None, 못 보면 Unavailable.

        os.path.exists()는 상위 디렉터리 권한이 없을 때도 False를 돌려줘서
        '없음'과 '못 봄'을 구분하지 못한다. 그래서 존재 확인은 이 함수로 한다.
        """
        try:
            return os.stat(self.path(p)) if follow else os.lstat(self.path(p))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            raise Unavailable("{} 접근 권한 없음 (root로 실행 필요)".format(p))

    def readlink(self, p: str) -> Optional[str]:
        try:
            return os.readlink(self.path(p))
        except OSError:
            return None

    def read_lines(self, p: str, missing_ok: bool = False) -> List[str]:
        """파일을 줄 단위로 읽는다.

        읽을 수 없으면 Unavailable을 낸다. 단 missing_ok=True면 파일이 없을 때만
        빈 목록을 돌려준다 (없어도 되는 파일용).
        """
        full = self.path(p)
        try:
            # FIFO나 장치 파일을 열면 진단 도구가 멈출 수 있으므로 일반 파일만 연다
            st = os.stat(full)
            if stat.S_ISDIR(st.st_mode):
                raise Unavailable("{} 이(가) 파일이 아니라 디렉터리임".format(p))
            if not stat.S_ISREG(st.st_mode):
                raise Unavailable("{} 이(가) 일반 파일이 아님 (읽지 않음)".format(p))
            with open(full, encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except (FileNotFoundError, NotADirectoryError):
            if missing_ok:
                return []
            raise Unavailable("{} 파일 없음".format(p))
        except PermissionError:
            raise Unavailable("{} 읽기 권한 없음 (root로 실행 필요)".format(p))

    def list_dir(self, p: str) -> List[str]:
        """디렉터리 안의 이름을 정렬해 돌려준다. 없으면 빈 목록, 못 읽으면 Unavailable."""
        try:
            return sorted(os.listdir(self.path(p)))
        except (FileNotFoundError, NotADirectoryError):
            return []
        except PermissionError:
            raise Unavailable("{} 디렉터리 읽기 권한 없음 (root로 실행 필요)".format(p))


class Check:
    # 하위 클래스에서 반드시 채운다
    id = None        # 예: "ACC-01"
    title = None
    severity = None  # critical / warning / info
    attack = None    # ATT&CK 기법 ID

    def run(self, ctx: Context) -> List[Finding]:
        raise NotImplementedError

    def finding(self, reason: str, next_steps: str, evidence: List[Evidence],
                timestamp: Optional[float] = None,
                severity: Optional[str] = None) -> Finding:
        """탐지 한 건을 만든다. severity를 주면 기본 위험도 대신 그 값을 쓴다."""
        return Finding(self.id, self.title, severity or self.severity, self.attack,
                       reason, next_steps, evidence, timestamp)
