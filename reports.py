"""
reports.py — PDF election report generation using ReportLab.
Exports a professional audit report including vote analytics,
anomaly summary, and election integrity score.
"""

import os
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from database import (
    get_vote_counts, get_audit_logs, get_anomaly_logs,
    get_total_votes, get_election_status
)
from anomaly_detection import compute_integrity_score


# ── Colour palette ────────────────────────────────────────────────────────────
NAVY    = colors.HexColor("#1A2744")
TEAL    = colors.HexColor("#00A896")
AMBER   = colors.HexColor("#F5A623")
RED     = colors.HexColor("#D0021B")
LIGHT   = colors.HexColor("#F4F6FA")
WHITE   = colors.white
GREY    = colors.HexColor("#6B7280")


def build_styles():
    styles = getSampleStyleSheet()
    custom = {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22,
                                 textColor=NAVY, alignment=TA_CENTER, spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=11,
                                    textColor=GREY, alignment=TA_CENTER, spaceAfter=20),
        "section": ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=13,
                                   textColor=NAVY, spaceBefore=16, spaceAfter=6),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10,
                                textColor=colors.black, spaceAfter=4),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                 textColor=GREY),
        "alert": ParagraphStyle("alert", fontName="Helvetica-Bold", fontSize=10,
                                 textColor=RED),
    }
    return custom


def generate_report(output_path: str = None) -> str:
    """Generate PDF report and return the file path."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(os.path.dirname(__file__), f"election_report_{ts}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = build_styles()
    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("AI-Powered Secure Voting System", styles["title"]))
    story.append(Paragraph("Official Election Audit Report", styles["subtitle"]))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y  %H:%M:%S')}   |   "
        f"Election Status: {get_election_status().upper()}",
        styles["small"]
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=12))

    # ── Integrity Score ────────────────────────────────────────────────────────
    score, status = compute_integrity_score()
    score_color = TEAL if score >= 90 else AMBER if score >= 70 else RED
    score_data = [
        ["Election Integrity Score", "Status"],
        [f"{score}%", status],
    ]
    score_table = Table(score_data, colWidths=[8*cm, 9*cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT),
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("TEXTCOLOR", (0, 1), (0, 1), score_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [LIGHT]),
        ("BOX", (0, 0), (-1, -1), 1, NAVY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 16))

    # ── Vote Counts ────────────────────────────────────────────────────────────
    story.append(Paragraph("Vote Distribution", styles["section"]))
    vote_counts = get_vote_counts()
    total = get_total_votes()

    if vote_counts:
        rows = [["Candidate", "Votes", "Percentage"]]
        for cand, cnt in sorted(vote_counts.items(), key=lambda x: -x[1]):
            pct = f"{cnt/total*100:.1f}%" if total > 0 else "0%"
            rows.append([cand, str(cnt), pct])
        rows.append(["TOTAL", str(total), "100%"])

        vote_table = Table(rows, colWidths=[9*cm, 4*cm, 4*cm])
        vote_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [WHITE, LIGHT]),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E8F4F8")),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 1, NAVY),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(vote_table)
    else:
        story.append(Paragraph("No votes recorded.", styles["body"]))

    story.append(Spacer(1, 12))

    # ── Anomaly Log ────────────────────────────────────────────────────────────
    story.append(Paragraph("Anomaly & Fraud Detection Log", styles["section"]))
    anomalies = get_anomaly_logs(limit=30)
    if anomalies:
        anom_rows = [["Timestamp", "Type", "User", "Risk Score", "Details"]]
        for a in anomalies:
            anom_rows.append([
                a["detected_at"][:16],
                a["anomaly_type"],
                a["username"] or "—",
                f"{a['anomaly_score']:.2f}" if a["anomaly_score"] else "—",
                Paragraph(a["details"] or "", ParagraphStyle("wrap", fontSize=7, leading=9))
            ])
        anom_table = Table(anom_rows, colWidths=[3*cm, 3.2*cm, 2.5*cm, 2.2*cm, 6.1*cm])
        anom_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), RED),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#FFF5F5")]),
            ("BOX", (0, 0), (-1, -1), 1, RED),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#FCA5A5")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(anom_table)
    else:
        story.append(Paragraph("✅ No anomalies detected.", styles["body"]))

    story.append(Spacer(1, 12))

    # ── Audit Trail (last 20) ─────────────────────────────────────────────────
    story.append(Paragraph("Recent Audit Trail (last 20 entries)", styles["section"]))
    logs = get_audit_logs(limit=20)
    if logs:
        log_rows = [["Timestamp", "Event", "User", "Severity", "Details"]]
        for entry in logs:
            sev_color = RED if entry["severity"] in ("CRITICAL", "WARNING") else colors.black
            log_rows.append([
                entry["timestamp"][:16],
                entry["event_type"],
                entry["username"] or "—",
                entry["severity"],
                Paragraph(entry["details"] or "", ParagraphStyle("wraplog", fontSize=7, leading=9))
            ])
        log_table = Table(log_rows, colWidths=[3*cm, 3.5*cm, 2.5*cm, 2*cm, 6*cm])
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT]),
            ("BOX", (0, 0), (-1, -1), 1, NAVY),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D1D5DB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(log_table)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=GREY))
    story.append(Paragraph(
        "This report was auto-generated by the AI-Powered Secure Voting System. "
        "All anomaly scores are computed using Isolation Forest and Local Outlier Factor algorithms.",
        styles["small"]
    ))

    doc.build(story)
    return output_path
