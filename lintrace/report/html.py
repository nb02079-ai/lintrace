"""HTML 리포트 (3단계 1차).

json_report.build()가 만든 결과 사전을 그대로 받아 단일 HTML 파일로 그린다 (수집·판정과 분리, 텍스트·JSON과
같은 자료). 외부 리소스·자바스크립트를 전혀 쓰지 않고, 접기는 HTML <details>로만 한다.

안전성: 리포트에는 공격자가 조종할 수 있는 내용(웹 로그의 <script>, 웹쉘 <?php>, SQLi 문자열, 파일 이름)이
그대로 들어간다. 모든 동적 문자열을 esc()로 이스케이프하고, <meta> CSP로 스크립트 실행 자체를 막아, 리포트를
브라우저로 열어도 그 내용이 실행되지 않게 한다.
"""
import html as _html

SEV = {
    "critical": ("심각", "crit", "●"),   # ●
    "warning": ("위험", "warn", "▲"),    # ▲
    "info": ("참고", "info", "■"),       # ■
}
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}
VERDICT_KO = {"critical": "심각", "warning": "위험", "clean": "정상"}
STATUS_KO = {"detected": "탐지", "clean": "이상 없음", "unavailable": "점검 불가"}

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"

STYLE = """
:root{
  --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5b636e; --line:#e2e5ea;
  --crit:#c0362c; --crit-bg:#fdecea; --warn:#b26a00; --warn-bg:#fff4e2; --info:#4a5568; --info-bg:#eef0f3;
  --ok:#2f855a;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#15181d; --card:#1d2127; --fg:#e6e9ee; --muted:#9aa3af; --line:#2c323b;
    --crit:#ff7b6e; --crit-bg:#3a201e; --warn:#f0b662; --warn-bg:#332814; --info:#aab3c0; --info-bg:#23272e;
    --ok:#6cc79a;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans KR",sans-serif;line-height:1.5;padding:24px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 10px;color:var(--muted)}
.notice{color:var(--muted);font-size:13px;margin:0 0 16px}
.meta{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-size:13px}
.meta dl{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;margin:0}
.meta dt{color:var(--muted)} .meta dd{margin:0;word-break:break-all}
.verdict{display:flex;align-items:center;gap:12px;margin:18px 0}
.badge{font-size:15px;font-weight:700;padding:6px 14px;border-radius:999px;border:1px solid}
.badge.crit{color:var(--crit);background:var(--crit-bg);border-color:var(--crit)}
.badge.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn)}
.badge.ok{color:var(--ok);background:transparent;border-color:var(--ok)}
.counts{color:var(--muted);font-size:14px}
.warnbox{background:var(--warn-bg);border:1px solid var(--warn);border-radius:8px;padding:10px 12px;margin:10px 0;font-size:13px}
details{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;margin:8px 0;overflow:hidden}
details.crit{border-left-color:var(--crit)} details.warn{border-left-color:var(--warn)} details.info{border-left-color:var(--info)}
summary{cursor:pointer;padding:11px 14px;font-weight:600;display:flex;gap:10px;align-items:baseline;list-style:none}
summary::-webkit-details-marker{display:none}
.chip{font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.chip.crit{color:var(--crit);background:var(--crit-bg)} .chip.warn{color:var(--warn);background:var(--warn-bg)} .chip.info{color:var(--info);background:var(--info-bg)}
.cid{font-variant-numeric:tabular-nums;color:var(--muted);font-weight:700}
.att{margin-left:auto;color:var(--muted);font-size:12px;font-weight:400}
.body{padding:2px 14px 14px;font-size:14px}
.body .reason{margin:4px 0 10px}
.body .steps{margin:10px 0 0;color:var(--muted);font-size:13px}
.ev{margin:8px 0;border-top:1px dashed var(--line);padding-top:8px}
.ev div{display:flex;gap:8px;padding:2px 0;font-size:12.5px}
.ev .src{color:var(--muted);flex:0 0 auto;max-width:38%;word-break:break-all;font-family:ui-monospace,Menlo,Consolas,monospace}
.ev .det{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600} tr:last-child td{border-bottom:none}
td.st-detected{color:var(--crit);font-weight:600} td.st-unavailable{color:var(--warn)} td.st-clean{color:var(--muted)}
.foot{color:var(--muted);font-size:12px;margin-top:24px;border-top:1px solid var(--line);padding-top:12px}
"""


def esc(s):
    return _html.escape("" if s is None else str(s), quote=True)


def _meta_rows(report):
    run = report.get("run", {})
    tool = report.get("tool", {})
    rows = [
        ("호스트", run.get("host")),
        ("운영체제", run.get("os")),
        ("커널", run.get("kernel")),
        ("점검 범위 루트", run.get("root")),
        ("실행 계정", "euid {}{}".format(run.get("euid"),
                                    " (sudo: {})".format(run["sudo_user"]) if run.get("sudo_user") else "")),
        ("시작", run.get("started")),
        ("끝", run.get("finished")),
        ("도구", "{} {}".format(tool.get("name"), tool.get("version"))),
        ("코드 SHA-256", tool.get("code_sha256")),
    ]
    out = []
    for k, v in rows:
        if v not in (None, ""):
            out.append("<dt>{}</dt><dd>{}</dd>".format(esc(k), esc(v)))
    return "".join(out)


def _finding_block(f):
    sev = f.get("severity", "info")
    label, cls, icon = SEV.get(sev, ("참고", "info", "■"))
    open_attr = " open" if sev in ("critical", "warning") else ""
    ev = []
    for e in f.get("evidence", []):
        src = esc(e.get("source"))
        det = esc(e.get("detail"))
        sha = e.get("sha256")
        if sha:
            det += '  <span class="src">sha256 {}</span>'.format(esc(sha))
        ev.append('<div><span class="src">{}</span><span class="det">{}</span></div>'.format(src, det))
    ev_html = '<div class="ev">{}</div>'.format("".join(ev)) if ev else ""
    return (
        '<details class="{cls}"{op}>'
        '<summary><span class="chip {cls}">{icon} {label}</span>'
        '<span class="cid">{cid}</span> {title}<span class="att">{att}</span></summary>'
        '<div class="body"><div class="reason">{reason}</div>{ev}'
        '<div class="steps">다음 확인: {steps}</div></div></details>'
    ).format(cls=cls, op=open_attr, icon=icon, label=label,
             cid=esc(f.get("_id")), title=esc(f.get("_title")), att=esc(f.get("attack")),
             reason=esc(f.get("reason")), ev=ev_html, steps=esc(f.get("next_steps")))


KIND_MARK = {"added": ("새로 생김", "warn", "＋"), "changed": ("내용 바뀜", "warn", "～"),
             "removed": ("사라짐", "info", "－")}


def _baseline_section(b):
    src = b.get("source", {})
    c = b.get("counts", {})
    out = ['<h2>기준선과 달라진 점</h2>']
    out.append('<div class="meta"><dl>'
               '<dt>기준선 출처</dt><dd>{host} · {kernel} · {os}</dd>'
               '<dt>기준선 생성</dt><dd>{created}</dd>'
               '<dt>기준선 코드 SHA-256</dt><dd>{sha}</dd>'
               '<dt>달라진 점</dt><dd>새로 생김 {a} · 바뀜 {ch} · 사라짐 {r}</dd></dl></div>'.format(
                   host=esc(src.get("host") or "?"), kernel=esc(src.get("kernel") or "?"),
                   os=esc(src.get("os") or "?"), created=esc(src.get("created") or "?"),
                   sha=esc(src.get("code_sha256") or "?"),
                   a=c.get("added", 0), ch=c.get("changed", 0), r=c.get("removed", 0)))
    out.append('<div class="warnbox">⚠ 기준선이 이미 침해된 뒤 찍혔다면 이 비교는 소용없습니다.</div>')
    if b.get("mismatch"):
        out.append('<div class="warnbox">⚠ 기준선과 현재 시스템이 다릅니다 ({}). 비교 결과를 믿기 어렵습니다.</div>'
                   .format(esc(b["mismatch"])))
    changes = b.get("changes", [])
    if not changes:
        out.append('<p class="notice">달라진 점이 없습니다.</p>')
        return "".join(out)
    out.append('<table><tr><th>구분</th><th>범주</th><th>내용</th></tr>')
    for ch in changes:
        label, cls, mark = KIND_MARK.get(ch.get("kind"), ("?", "info", "·"))
        out.append('<tr><td class="st-{cls2}">{mark} {label}</td><td>{cat}</td><td class="det">{detail}</td></tr>'
                   .format(cls2=("detected" if cls == "warn" else "clean"), mark=mark, label=esc(label),
                           cat=esc(ch.get("category_ko")), detail=esc(ch.get("detail"))))
    out.append("</table>")
    return "".join(out)


def render(report):
    """report: json_report.build()가 돌려준 사전."""
    # 모든 항목의 탐지를 평평하게 펴고 (심각→위험→참고, 같은 등급은 항목 ID 순) 항목 정보(id·제목·attack)를 붙인다
    flat = []
    for item in report.get("checks", []):
        for f in item.get("findings", []):
            g = dict(f)
            g["_id"], g["_title"] = item["id"], item["title"]
            g.setdefault("attack", item.get("attack"))
            flat.append(g)
    flat.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("_id")))

    counts = report.get("counts", {})
    verdict = report.get("verdict", "clean")
    vlabel = VERDICT_KO.get(verdict, verdict)
    vcls = {"critical": "crit", "warning": "warn", "clean": "ok"}.get(verdict, "ok")
    incomplete = report.get("incomplete")

    parts = []
    parts.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append('<meta http-equiv="Content-Security-Policy" content="{}">'.format(CSP))
    parts.append("<title>LinTrace 진단 리포트 — {}</title>".format(esc(report.get("run", {}).get("host") or "")))
    parts.append("<style>{}</style></head><body><div class=\"wrap\">".format(STYLE))

    parts.append("<h1>LinTrace 침해 흔적 진단 리포트</h1>")
    parts.append('<p class="notice">본인 소유이거나 점검 권한을 받은 시스템에서만 실행하세요. '
                 '이 도구는 시스템을 수정하지 않습니다. 이 리포트는 외부 자원을 쓰지 않으며, 포함된 로그·파일 내용은 '
                 '실행되지 않도록 그대로 표시만 됩니다.</p>')

    parts.append('<div class="verdict"><span class="badge {vcls}">전체 판정: {v}</span>'
                 '<span class="counts">점검 {c}개 / 탐지 {d}건 (심각 {cr} · 위험 {wa} · 참고 {inf}) / 점검 불가 {u}개</span></div>'
                 .format(vcls=vcls, v=esc(vlabel), c=counts.get("checks", 0), d=counts.get("findings", 0),
                         cr=counts.get("critical", 0), wa=counts.get("warning", 0), inf=counts.get("info", 0),
                         u=counts.get("unavailable", 0)))
    if incomplete:
        parts.append('<div class="warnbox">점검 불가 항목이 있어 ‘정상’이 확정이 아닙니다 — 아래 ‘점검 불가’ '
                     '목록의 항목은 확인되지 않았습니다.</div>')
    for w in report.get("report_warnings", []):
        parts.append('<div class="warnbox">⚠ {}</div>'.format(esc(w)))

    parts.append('<h2>실행 정보</h2><div class="meta"><dl>{}</dl></div>'.format(_meta_rows(report)))

    parts.append("<h2>탐지 결과 ({}건)</h2>".format(len(flat)))
    if flat:
        parts.extend(_finding_block(f) for f in flat)
    else:
        parts.append('<p class="notice">탐지된 흔적이 없습니다.</p>')

    if report.get("baseline") is not None:
        parts.append(_baseline_section(report["baseline"]))

    parts.append("<h2>점검 범위 (전체 {}개 항목)</h2>".format(len(report.get("checks", []))))
    parts.append("<table><tr><th>항목</th><th>제목</th><th>결과</th><th>확인 범위</th></tr>")
    for item in report.get("checks", []):
        status = item.get("status", "clean")
        n = len(item.get("findings", []))
        st_txt = "탐지 {}건".format(n) if status == "detected" else STATUS_KO.get(status, status)
        scope = item.get("scope") or ("—" if status != "unavailable" else esc(item.get("error") or ""))
        parts.append('<tr><td class="cid">{id}</td><td>{title}</td><td class="st-{st}">{sttxt}</td><td>{scope}</td></tr>'
                     .format(id=esc(item["id"]), title=esc(item["title"]), st=esc(status), sttxt=esc(st_txt),
                             scope=esc(scope) if item.get("scope") else scope))
    parts.append("</table>")

    unavailable = [it for it in report.get("checks", []) if it.get("status") == "unavailable"]
    if unavailable:
        parts.append("<h2>점검 불가 (결과에 포함되지 않음)</h2><table><tr><th>항목</th><th>이유</th></tr>")
        for it in unavailable:
            parts.append('<tr><td class="cid">{}</td><td>{}</td></tr>'.format(esc(it["id"]), esc(it.get("error"))))
        parts.append("</table>")

    tool = report.get("tool", {})
    parts.append('<div class="foot">LinTrace {} · 코드 SHA-256 {} · 생성 {}</div>'.format(
        esc(tool.get("version")), esc(tool.get("code_sha256")), esc(report.get("run", {}).get("finished"))))
    parts.append("</div></body></html>")
    return "".join(parts)
