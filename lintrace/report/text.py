"""1단계용 텍스트 리포트. 3단계에서 HTML 리포트로 확장한다."""
LABEL = {"critical": "심각", "warning": "위험", "info": "참고"}


def verdict(findings):
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return "심각"
    if "warning" in sev:
        return "위험"
    return "정상"


def render(findings, ran_ids):
    out = [f"전체 판정: {verdict(findings)}",
           f"실행한 점검 {len(ran_ids)}개 / 탐지 {len(findings)}건", ""]
    for f in findings:
        out.append(f"[{LABEL[f.severity]}] {f.check_id} {f.title} ({f.attack})")
        out.append(f"  이유: {f.reason}")
        for e in f.evidence:
            out.append(f"  근거: {e.source} — {e.detail}")
        out.append(f"  다음 확인: {f.next_steps}")
        out.append("")
    hit = {f.check_id for f in findings}
    clean = [i for i in ran_ids if i not in hit]
    if clean:
        out.append("이상 없음: " + ", ".join(clean))
    return "\n".join(out)
