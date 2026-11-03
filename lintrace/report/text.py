"""1단계용 텍스트 리포트. 3단계에서 HTML 리포트로 확장한다."""
LABEL = {"critical": "심각", "warning": "위험", "info": "참고"}


def verdict(findings):
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return "심각"
    if "warning" in sev:
        return "위험"
    return "정상"


def render(findings, ran_ids, unavailable=None, scopes=None, warnings=None):
    """findings: 탐지 목록, ran_ids: 실행한 항목 ID, unavailable: [(항목 ID, 이유)],
    scopes: {항목 ID: 확인 범위}, warnings: 결과 전체의 신뢰도에 관한 경고 문장"""
    unavailable = unavailable or []
    scopes = scopes or {}
    head = "전체 판정: {}".format(verdict(findings))
    if unavailable:
        # 점검하지 못한 항목이 있으면 '정상'이 확정이 아님을 판정 줄에서 바로 알린다
        head += " (단, 점검 불가 {}개 — 아래 '점검 불가' 항목은 확인되지 않음)".format(len(unavailable))
    out = [head]
    for w in warnings or []:
        # 결과 자체를 믿을 수 있는지에 관한 경고는 판정 바로 아래에 둔다
        out.append("⚠ " + w)
    out += ["실행한 점검 {}개 / 탐지 {}건 / 점검 불가 {}개".format(
        len(ran_ids), len(findings), len(unavailable)), ""]
    for f in findings:
        out.append("[{}] {} {} ({})".format(LABEL.get(f.severity, f.severity), f.check_id, f.title, f.attack))
        out.append("  이유: {}".format(f.reason))
        for e in f.evidence:
            out.append("  근거: {} — {}".format(e.source, e.detail))
        out.append("  다음 확인: {}".format(f.next_steps))
        out.append("")
    if unavailable:
        out.append("점검 불가 (결과에 포함되지 않음):")
        for check_id, reason in unavailable:
            out.append("  {} — {}".format(check_id, reason))
        out.append("")
    # 모든 항목이 무엇을 보고 어떤 결과를 냈는지 한곳에 모은다.
    # "17개를 보고 1개를 찾았다"가 보여야 탐지 결과와 오탐 수준을 함께 판단할 수 있다.
    counts = {}
    for f in findings:
        counts[f.check_id] = counts.get(f.check_id, 0) + 1
    skipped = {i for i, _ in unavailable}
    out.append("점검 범위:")
    for i in ran_ids:
        if i in skipped:
            status = "점검 불가"
        elif i in counts:
            status = "탐지 {}건".format(counts[i])
        else:
            status = "이상 없음"
        if i in scopes and i not in skipped:
            out.append("  {} — {} 확인 ({})".format(i, scopes[i], status))
        else:
            out.append("  {} — {}".format(i, status))
    return "\n".join(out)
