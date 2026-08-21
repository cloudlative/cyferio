"""PDF report generation (Phase 4, spec section 18: "Security Summary
Report", "Firewall Configuration Report", "SSH Configuration Report",
"System Configuration Report", plus a "Full Report" covering every
category). CSV export (routes/system_audit.py's export_run_csv) already
covers the raw-data/spreadsheet use case; this covers the
print/share-with-someone-who-isn't-going-to-open-a-CSV use case the spec
asks for by name.

Built with reportlab (this repo's first PDF dependency -- no PDF library
existed here before Phase 4, see this module's own addition to
requirements.txt) rather than hand-rolling the PDF format: reportlab is a
mature, widely-used, permissively-licensed library and the alternative
(hand-writing PDF object/xref structures) would be a lot of fragile code
to maintain for something a well-tested library already does correctly.

Every report is built from data already in AuditRun/AuditFinding -- no
new queries, no host access, nothing privileged. This module only ever
reads; it has no remediation/execution capability at all."""
from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _esc

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

# Plain "#rrggbb" strings, not reportlab Color objects -- these go
# straight into a <font color="..."> tag, which wants CSS-style hex, not
# reportlab's own Color.hexval() format ("0xrrggbb").
_SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#4d7c0f",
    "info": "#1d4ed8",
    "passed": "#15803d",
}

REPORT_TITLES = {
    "full": "Full System Audit Report",
    "summary": "Security Summary Report",
    "firewall": "Firewall Configuration Report",
    "ssh": "SSH Configuration Report",
    "system": "System Configuration Report",
}
_REPORT_CATEGORIES = {"firewall": "firewall", "ssh": "ssh", "system": "system"}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("SA_Body", parent=ss["BodyText"], fontSize=9, leading=12))
    ss.add(ParagraphStyle("SA_Small", parent=ss["BodyText"], fontSize=8, leading=10, textColor=colors.grey))
    ss.add(ParagraphStyle("SA_FindingTitle", parent=ss["Heading4"], fontSize=10, spaceBefore=8, spaceAfter=2))
    return ss


def _overview_table(run, ss) -> Table:
    rows = [
        ["Security Score", f"{run.score if run.score is not None else '-'} / 100"],
        ["Run Date", run.started_at.strftime("%Y-%m-%d %H:%M UTC") if run.started_at else "-"],
        ["Node", run.node_hostname or "-"],
        ["Trigger", f"{run.trigger}" + (f" (by {run.triggered_by})" if run.triggered_by else "")],
        ["Critical", str(run.critical_count)],
        ["High", str(run.high_count)],
        ["Medium", str(run.medium_count)],
        ["Low", str(run.low_count)],
        ["Informational", str(run.info_count)],
        ["Passed", str(run.passed_count)],
        ["New since last run", str(run.new_findings_count)],
        ["Resolved since last run", str(run.resolved_findings_count)],
    ]
    t = Table(rows, colWidths=[2.2 * inch, 3.5 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    return t


def _esc_multiline(text: str) -> str:
    """Escapes for reportlab's mini-XML Paragraph markup, then restores
    line breaks as <br/> -- must escape FIRST, so a literal '<' in
    host-derived text (e.g. firewall remediation text like "-s <ip/cidr>")
    can never be mistaken for markup."""
    return _esc(text).replace("\n", "<br/>")


def _finding_flowables(f, ss) -> list:
    color = _SEVERITY_COLORS.get(f.severity, "#000000")
    out = [Paragraph(
        f'<font color="{color}">&#9679;</font> '
        f'<b>{_esc(f.title)}</b> &nbsp;'
        f'<font size="8" color="#6b7280">[{_esc(f.severity.upper())} / {_esc(f.category)} / {_esc(f.check_id)}]</font>',
        ss["SA_FindingTitle"],
    )]
    if f.description:
        out.append(Paragraph(_esc_multiline(f.description), ss["SA_Body"]))
    if f.why_it_matters:
        out.append(Paragraph(f"<b>Why it matters:</b> {_esc_multiline(f.why_it_matters)}", ss["SA_Body"]))
    if f.current_state:
        out.append(Paragraph(f"<b>Current state:</b> {_esc_multiline(f.current_state)}", ss["SA_Body"]))
    if f.expected_state:
        out.append(Paragraph(f"<b>Expected state:</b> {_esc_multiline(f.expected_state)}", ss["SA_Body"]))
    if f.remediation:
        out.append(Paragraph(f"<b>Remediation:</b> {_esc_multiline(f.remediation)}", ss["SA_Body"]))
    if f.remediated_at:
        out.append(Paragraph(
            f"<b>Fixed automatically</b> by {_esc(f.remediated_by or 'an admin')} on "
            f"{f.remediated_at.strftime('%Y-%m-%d %H:%M UTC')}.", ss["SA_Small"],
        ))
    return out


def build_run_pdf(run, report: str = "full") -> bytes:
    """Renders one AuditRun to a PDF, returned as raw bytes. `report`
    selects scope: "full" (every category), "summary" (overview + only
    non-passed findings, no full catalog), or one of "firewall"/"ssh"/
    "system" (that category's findings only, every severity including
    passed -- this IS that category's full report)."""
    if report not in REPORT_TITLES:
        report = "full"
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        title=REPORT_TITLES[report],
    )
    story = [
        Paragraph(REPORT_TITLES[report], ss["Title"]),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} -- "
            f"System Audit run #{run.id}", ss["SA_Small"],
        ),
        Spacer(1, 0.2 * inch),
        _overview_table(run, ss),
        Spacer(1, 0.25 * inch),
    ]

    if report == "summary":
        findings = [f for f in run.findings if f.severity != "passed"]
        story.append(Paragraph("Findings Requiring Attention", ss["Heading2"]))
        if not findings:
            story.append(Paragraph("No open findings -- every check passed.", ss["SA_Body"]))
    else:
        category = _REPORT_CATEGORIES.get(report)
        findings = [f for f in run.findings if category is None or f.category == category]
        story.append(Paragraph("Findings", ss["Heading2"]))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "passed": 5}
    findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 9))
    for f in findings:
        story.extend(_finding_flowables(f, ss))

    doc.build(story)
    return buf.getvalue()
