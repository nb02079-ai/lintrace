"""점검 항목의 공통 틀.

모든 점검 항목은 Check를 상속하고 run()에서 Finding 목록을 돌려준다.
파일 경로는 항상 ctx.path()로 만든다. 그래야 테스트에서 가짜 루트(fixture)를
가리켜 실제 시스템 없이 점검 로직을 검증할 수 있다.

Python 3.6 호환을 유지한다 (Ubuntu 18.04 기본 버전).
dataclasses, `from __future__ import annotations`, `X | None`, `list[...]` 표기는 쓰지 않는다.
"""
import os
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


class Context:
    """점검 실행 환경. root는 기본 '/'이고 테스트에서는 fixture 디렉터리."""

    def __init__(self, root: str = "/"):
        self.root = root

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def read_lines(self, p: str) -> List[str]:
        try:
            with open(self.path(p), encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return []


class Check:
    # 하위 클래스에서 반드시 채운다
    id = None        # 예: "ACC-01"
    title = None
    severity = None  # critical / warning / info
    attack = None    # ATT&CK 기법 ID

    def run(self, ctx: Context) -> List[Finding]:
        raise NotImplementedError

    def finding(self, reason: str, next_steps: str, evidence: List[Evidence],
                timestamp: Optional[float] = None) -> Finding:
        return Finding(self.id, self.title, self.severity, self.attack,
                       reason, next_steps, evidence, timestamp)
