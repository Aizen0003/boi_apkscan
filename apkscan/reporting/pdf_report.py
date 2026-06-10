"""PDF report rendering (reportlab). Renders the same content as the JSON report.

All dynamic text (which may include untrusted APK-derived strings) is XML-escaped
before being placed into flowables.
"""

from io import BytesIO
from typing import List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from apkscan.schema import ReportDocument, Verdict

_VERDICT_COLORS = {
    Verdict.BENIGN: colors.HexColor("#1b7f3b"),
    Verdict.SUSPICIOUS: colors.HexColor("#b8860b"),
    Verdict.MALICIOUS: colors.HexColor("#b00020"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7.5, leading=9))
    styles.add(ParagraphStyle("H2x", parent=styles["Heading2"], spaceBefore=10, spaceAfter=4))
    return styles


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def render_pdf(report: ReportDocument) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, title=f"APKScan Report — {report.sample.sha256[:16]}",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    s = _styles()
    flow: List = []

    flow.append(Paragraph("APKScan — Android Malware Analysis Report", s["Title"]))
    flow.append(_p(report.analyst_signoff_required_disclaimer, s["Small"]))
    flow.append(Spacer(1, 6))

    # --- sample metadata ---
    meta = report.sample
    meta_rows = [
        ["Package", meta.package_name or "—", "Version", f"{meta.version_name or '—'} ({meta.version_code or '—'})"],
        ["SHA-256", meta.sha256, "File", meta.file_name or "—"],
        ["Size", f"{meta.file_size} bytes", "SDK", f"min {meta.min_sdk or '—'} / target {meta.target_sdk or '—'}"],
        ["Generated", str(report.generated_at), "Report ID", report.report_id or "—"],
    ]
    flow.append(_kv_table(meta_rows, s))
    flow.append(Spacer(1, 8))

    # --- verdict banner ---
    v = report.verdict
    color = _VERDICT_COLORS.get(v.verdict, colors.grey)
    banner = Table(
        [[Paragraph(f"<b>{escape(v.verdict.value.upper())}</b> — severity {escape(v.severity.value)}", _white(s)),
          Paragraph(f"Risk score <b>{v.risk_score:.1f}/100</b>  ·  confidence <b>{v.confidence:.2f}</b>  ·  mode {escape(v.operating_mode)}", _white(s))]],
        colWidths=[60 * mm, 110 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(banner)
    signoff = report.signoff
    flow.append(_p(f"Sign-off: {signoff.status}"
                   + (f" by {signoff.signed_by}" if signoff.signed_by else "")
                   + (f" — {signoff.decision}" if signoff.decision else ""), s["Small"]))
    flow.append(Spacer(1, 4))
    flow.append(_p(v.rationale, s["Normal"]))
    flow.append(Spacer(1, 8))

    # --- summary ---
    flow.append(Paragraph("Summary", s["H2x"]))
    flow.append(_p(report.summary, s["Normal"]))

    # --- evidence log ---
    flow.append(Paragraph("Evidence log", s["H2x"]))
    flow.append(_evidence_table(report, s))

    # --- ATT&CK ---
    if report.attack:
        flow.append(Paragraph("MITRE ATT&CK for Mobile (v19.1) mapping", s["H2x"]))
        flow.append(_attack_table(report, s))

    # --- IOCs ---
    flow.append(Paragraph("Indicators of Compromise (IOCs)", s["H2x"]))
    flow.append(_ioc_flow(report, s))

    # --- recommendations ---
    flow.append(Paragraph("Recommendations", s["H2x"]))
    flow.append(_bullets(report.recommendations, s))

    # --- GenAI interpretation (clearly marked non-deciding) ---
    flow.append(Paragraph("GenAI interpretation (explanatory only — does not decide the verdict)", s["H2x"]))
    flow.append(_genai_flow(report, s))

    # --- escalation / gaps ---
    if report.escalation.escalate or report.analysis_gaps:
        flow.append(Paragraph("Analysis caveats", s["H2x"]))
        if report.escalation.escalate:
            flow.append(_p("Escalation flagged: " + "; ".join(report.escalation.reasons), s["Small"]))
        for gap in report.analysis_gaps:
            flow.append(_p(f"[{gap.severity}] {gap.tool}: {gap.reason}", s["Small"]))

    doc.build(flow)
    return buf.getvalue()


def _white(s):
    return ParagraphStyle("White", parent=s["Normal"], textColor=colors.white, fontSize=10)


def _kv_table(rows, s):
    data = [[_p(c, s["Cell"]) for c in row] for row in rows]
    t = Table(data, colWidths=[22 * mm, 63 * mm, 22 * mm, 63 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("BACKGROUND", (2, 0), (2, -1), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _evidence_table(report, s):
    header = [_p(h, s["Cell"]) for h in ("Category", "Indicator", "Layer", "Wt", "ATT&CK")]
    data = [header]
    for e in report.evidence:
        data.append([
            _p(e.category, s["Cell"]),
            _p(e.title, s["Cell"]),
            _p(e.layer.value, s["Cell"]),
            _p(f"{e.weight:g}", s["Cell"]),
            _p(", ".join(e.attack_techniques) or "—", s["Cell"]),
        ])
    if len(data) == 1:
        data.append([_p("—", s["Cell"])] * 5)
    t = Table(data, colWidths=[26 * mm, 86 * mm, 16 * mm, 10 * mm, 32 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#22303f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _attack_table(report, s):
    header = [_p(h, s["Cell"]) for h in ("Technique", "Name", "Tactics")]
    data = [header]
    for a in report.attack:
        data.append([_p(a.id, s["Cell"]), _p(a.name, s["Cell"]), _p(", ".join(a.tactics), s["Cell"])])
    t = Table(data, colWidths=[24 * mm, 76 * mm, 70 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#22303f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _ioc_flow(report, s):
    iocs = report.iocs
    items = []
    for label, values in (
        ("Domains", iocs.domains), ("URLs", iocs.urls), ("IPs", iocs.ips),
        ("Firebase", iocs.firebase_urls), ("Emails", iocs.emails), ("Crypto", iocs.crypto_constants),
    ):
        if values:
            items.append(_p(f"<b>{label}:</b> " + ", ".join(values), s["Small"]))
    if not items:
        items.append(_p("None extracted.", s["Small"]))
    return _stack(items)


def _genai_flow(report, s):
    g = report.genai
    items = []
    if not g.generated:
        items.append(_p("GenAI interpretation not applied (disabled/unavailable). "
                        "Verdict is purely deterministic.", s["Small"]))
        return _stack(items)
    items.append(_p(f"Model: {g.model_name or '—'}  ·  grounded claims: {len(g.claims)}  ·  "
                    f"withheld: {len(g.withheld_claims)}  ·  grounding-failure: {g.grounding_failure_rate:.0%}", s["Small"]))
    flags = []
    if g.prompt_injection_detected:
        flags.append("prompt-injection text detected in sample (isolated as data)")
    if g.truncated:
        flags.append("input truncated/partial")
    if flags:
        items.append(_p("Flags: " + "; ".join(flags), s["Small"]))
    for c in g.claims:
        items.append(_p(f"• {c.text}  [{', '.join(c.artifact_refs) or 'n/a'}]", s["Small"]))
    if g.warnings:
        items.append(_p("Warnings: " + "; ".join(g.warnings), s["Small"]))
    return _stack(items)


def _bullets(values, s):
    if not values:
        return _p("None.", s["Small"])
    return ListFlowable([ListItem(_p(v, s["Normal"]), leftIndent=10) for v in values], bulletType="bullet")


def _stack(items):
    out = []
    for i, item in enumerate(items):
        out.append(item)
        if i < len(items) - 1:
            out.append(Spacer(1, 2))
    table = Table([[i] for i in out], colWidths=[170 * mm])
    table.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return table
