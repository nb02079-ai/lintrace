import argparse
import json
import os
import sys

from . import __version__
from .checks import ALL_CHECKS
from .checks.base import Context
from .report import text

NOTICE = "본인 소유이거나 점검 권한을 받은 시스템에서만 실행하세요. 이 도구는 시스템을 수정하지 않습니다."


def load_catalog():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "catalog.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    p = argparse.ArgumentParser(prog="lintrace", description="Ubuntu 서버 침해 흔적 진단")
    p.add_argument("--list", action="store_true", help="점검 항목 목록과 구현 상태 출력")
    p.add_argument("--root", default="/", help="점검할 파일시스템 루트 (테스트용)")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    done = {c.id for c in ALL_CHECKS}
    if args.list:
        for c in load_catalog():
            mark = "구현" if c["id"] in done else "예정"
            print(f'{c["id"]:7} [{mark}] {c["name"]}')
        print(f"\n구현 {len(done)} / 전체 {len(load_catalog())}")
        return 0

    print(NOTICE, file=sys.stderr)
    if args.root == "/" and os.geteuid() != 0:
        print("경고: root가 아니면 일부 파일을 읽지 못해 결과가 불완전합니다.", file=sys.stderr)

    ctx = Context(args.root)
    findings = []
    for cls in ALL_CHECKS:
        findings.extend(cls().run(ctx))
    print(text.render(findings, [c.id for c in ALL_CHECKS]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
