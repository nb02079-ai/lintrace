"""LinTrace — Ubuntu 서버 침해 흔적 원클릭 진단 도구."""
import hashlib
import os

__version__ = "0.1.0"

CODE_DIRS = ("lintrace", "tests", "rules")
CODE_EXT = (".py", ".json")


def code_sha256(base=None):
    """실행 중인 코드의 지문.

    검증 기록에 쓰는 셸 명령과 같은 값이 나온다:
      find lintrace tests rules -type f \\( -name '*.py' -o -name '*.json' \\) | LC_ALL=C sort | xargs sha256sum | sha256sum
    결과 파일만 보고도 어떤 코드로 나온 결과인지 알 수 있게 JSON에 넣는다. 읽을 수 없으면 None.
    """
    base = base or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = []
    for top in CODE_DIRS:
        for d, _, files in os.walk(os.path.join(base, top)):
            for name in files:
                if name.endswith(CODE_EXT):
                    paths.append(os.path.relpath(os.path.join(d, name), base).replace(os.sep, "/"))
    lines = []
    try:
        for rel in sorted(paths, key=lambda p: p.encode("utf-8")):
            h = hashlib.sha256()
            with open(os.path.join(base, rel), "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            lines.append("{}  {}\n".format(h.hexdigest(), rel))
    except OSError:
        return None
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
