"""점검 항목의 공통 틀.

모든 점검 항목은 Check를 상속하고 run()에서 Finding 목록을 돌려준다.
파일 경로는 항상 ctx.path()로 만든다. 그래야 테스트에서 가짜 루트(fixture)를
가리켜 실제 시스템 없이 점검 로직을 검증할 수 있다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class Evidence:
    """판정 근거가 된 원본 증거 한 건."""
    source: str            # 파일 경로나 명령 이름
    detail: str            # 해당 줄, 값 등
    sha256: str | None = None


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str          # critical / warning / info
    attack: str
    reason: str            # 왜 의심스러운지
    next_steps: str        # 다음에 확인할 것
    evidence: list[Evidence] = field(default_factory=list)
    timestamp: float | None = None   # 상관분석용 (알 수 있을 때만)


class Context:
    """점검 실행 환경. root는 기본 '/'이고 테스트에서는 fixture 디렉터리."""

    def __init__(self, root: str = "/"):
        self.root = root

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def read_lines(self, p: str) -> list[str]:
        try:
            with open(self.path(p), encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except (FileNotFoundError, PermissionError):
            return []


class Check:
    id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[str]
    attack: ClassVar[str]

    def run(self, ctx: Context) -> list[Finding]:
        raise NotImplementedError

    def finding(self, reason: str, next_steps: str, evidence: list[Evidence],
                timestamp: float | None = None) -> Finding:
        return Finding(self.id, self.title, self.severity, self.attack,
                       reason, next_steps, evidence, timestamp)
