import argparse
import json
import os
import sys

from . import __version__
from .checks import ALL_CHECKS
from .checks.base import Context, Unavailable
from . import archive
from .report import json_report, text

NOTICE = "본인 소유이거나 점검 권한을 받은 시스템에서만 실행하세요. 이 도구는 시스템을 수정하지 않습니다."


def load_catalog():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "catalog.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    p = argparse.ArgumentParser(prog="lintrace", description="Ubuntu 서버 침해 흔적 진단")
    p.add_argument("--list", action="store_true", help="점검 항목 목록과 구현 상태 출력")
    p.add_argument("--root", default="/", help="점검할 파일시스템 루트 (테스트용)")
    p.add_argument("--json", metavar="FILE", help="JSON 결과를 파일로 저장 ('-'면 텍스트 대신 화면에 JSON 출력)")
    p.add_argument("--out", metavar="DIR", help="증거 아카이브를 만들 폴더 (탐지 근거 파일 복사본, 해시 목록, tar.gz)")
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
    started = json_report.now_iso()
    findings, unavailable, scopes, warnings = run_checks(ctx, ALL_CHECKS)
    report_text = text.render(findings, [c.id for c in ALL_CHECKS], unavailable, scopes, warnings)
    report = json_report.build(ctx, ALL_CHECKS, findings, unavailable, scopes, warnings, started)
    report_json = json.dumps(report, ensure_ascii=False, indent=2)

    if args.json == "-":
        print(report_json)
    else:
        print(report_text)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(report_json + "\n")
            print("JSON 결과: {}".format(args.json), file=sys.stderr)

    if args.out:
        try:
            folder, tar_path, digest, copied, sources = archive.write(
                args.out, ctx, report["run"]["host"], ctx.now, findings, report_text, report)
        except OSError as e:
            print("증거 아카이브를 만들지 못함: {}".format(e), file=sys.stderr)
            return 1
        print("증거 아카이브: {} (근거 경로 {}개 중 파일 {}개 복사)".format(folder, sources, copied), file=sys.stderr)
        print("묶음: {}".format(tar_path), file=sys.stderr)
        print("묶음 SHA-256: {}".format(digest), file=sys.stderr)
        print("주의: 원본 파일을 그대로 복사해 비밀번호 해시 등 민감 정보가 들어 있을 수 있습니다. "
              "안전한 곳으로 옮기고 접근을 제한하세요.", file=sys.stderr)
    return 0


def run_checks(ctx, checks):
    """모든 항목을 실행한다. 한 항목이 실패해도 나머지는 계속 돈다.

    돌려주는 값: (탐지 목록, [(항목 ID, 점검 불가 이유)], {항목 ID: 확인 범위},
                 [결과 전체에 대한 경고 문장])
    """
    findings, unavailable, scopes, warnings = [], [], {}, []
    for cls in checks:
        check = cls()
        try:
            findings.extend(check.run(ctx))
            if check.scope:
                scopes[cls.id] = check.scope
            warnings.extend(check.report_warnings or [])
        except Unavailable as e:
            unavailable.append((cls.id, str(e)))
        except Exception as e:  # 항목 하나의 버그가 전체 진단을 멈추지 않게 한다
            unavailable.append((cls.id, "점검 중 오류 — {}: {}".format(type(e).__name__, e)))
    return findings, unavailable, scopes, warnings


if __name__ == "__main__":
    sys.exit(main())
