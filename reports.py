"""
HawkEye report exporters — builds a professional PDF report and a
CSV export from an analysis result dict.
"""

import csv
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

NAVY = colors.HexColor("#0f172a")
BLUE = colors.HexColor("#2563eb")
LIGHT_BLUE = colors.HexColor("#38bdf8")
RED = colors.HexColor("#dc2626")
GREEN = colors.HexColor("#16a34a")
AMBER = colors.HexColor("#eab308")
SLATE = colors.HexColor("#475569")
LIGHT_GREY = colors.HexColor("#f1f5f9")

RISK_COLORS = {"high": RED, "medium": AMBER, "low": GREEN}


def build_pdf_report(data, logo_path=None):
    """Return a BytesIO buffer containing a PDF report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18 * mm, bottomMargin=18 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
        title="HawkEye Security Analysis Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "HawkTitle", parent=styles["Title"], textColor=NAVY, fontSize=24,
        spaceAfter=2, alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "HawkSubtitle", parent=styles["Normal"], textColor=SLATE, fontSize=11,
        alignment=TA_CENTER, spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "HawkH2", parent=styles["Heading2"], textColor=BLUE, fontSize=14,
        spaceBefore=16, spaceAfter=8,
    )
    body_style = ParagraphStyle(
    "HawkBody",
    parent=styles["BodyText"],
    fontName="Helvetica",
    fontSize=9,
    leading=12,
    textColor=colors.HexColor("#1e293b"),
    wordWrap="CJK",
    splitLongWords=True,
    allowWidows=1,
    allowOrphans=1,
)

    story = []

    if logo_path:
        try:
            story.append(Image(logo_path, width=26 * mm, height=26 * mm))
        except Exception:
            pass

    story.append(Paragraph("HawkEye Security Analysis Report", title_style))
    story.append(Paragraph("Intelligent Security Log Analysis System", subtitle_style))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1"), thickness=1))

    # --- Summary info table ---
    story.append(Paragraph("Analysis Information", h2_style))
    info_rows = [
        ["File Name", data.get("filename", "N/A")],
        ["Analysis Time", data.get("analysis_time", "N/A")],
        ["Top Suspicious IP", data.get("top_ip", "N/A")],
        ["Highest Attempts (single IP)", str(data.get("attempts", 0))],
        ["Unique Source IPs", str(data.get("unique_ips", 0))],
        ["Unique Usernames Targeted", str(data.get("unique_users", 0))],
    ]
    t = Table(info_rows, colWidths=[65 * mm, 95 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # --- Threat assessment ---
    story.append(Paragraph("Threat Assessment", h2_style))
    risk_color = RISK_COLORS.get(data.get("risk_class", "low"), GREEN)
    assess_rows = [
        ["Risk Level", data.get("risk", "N/A")],
        ["Threat Score", f"{data.get('threat_score', 0)} / 100"],
        ["Brute Force Detected", data.get("brute_force", "No")],
        ["Failed Authentication Events", str(data.get("failed", 0))],
        ["Successful Authentication Events", str(data.get("success", 0))],
        ["Total Events", str(data.get("total", 0))],
    ]
    t2 = Table(assess_rows, colWidths=[65 * mm, 95 * mm])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t2)

    # --- Top 5 suspicious IPs ---
    story.append(Paragraph("Top 5 Suspicious IP Addresses", h2_style))
    top_ips = data.get("top_ips", [])
    if top_ips:
        rows = [["#", "IP Address", "Failed Attempts", "Successful Logins"]]
        for i, item in enumerate(top_ips, 1):
            rows.append([str(i), item["ip"], str(item["failed"]), str(item["success"])])
        t3 = Table(rows, colWidths=[10 * mm, 60 * mm, 45 * mm, 45 * mm])
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t3)
    else:
        story.append(Paragraph("No suspicious IP activity recorded.", body_style))

    # --- Username attack statistics ---
    story.append(Paragraph("Username Attack Statistics", h2_style))
    top_users = data.get("top_users", [])
    if top_users:
        rows = [["#", "Username", "Failed Attempts"]]
        for i, item in enumerate(top_users, 1):
            rows.append([str(i), item["username"], str(item["attempts"])])
        t4 = Table(rows, colWidths=[10 * mm, 90 * mm, 60 * mm])
        t4.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t4)
    else:
        story.append(Paragraph("No targeted usernames recorded.", body_style))

    # --- Attack timeline ---
    timeline = data.get("timeline", [])
    if timeline:
        story.append(Paragraph("Attack Timeline (Failed Attempts per Hour)", h2_style))
        rows = [["Time Bucket", "Failed Attempts"]]
        for row in timeline:
            bucket, count = row.get("time", ""), row.get("count", 0)
            rows.append([bucket, str(count)])
        t5 = Table(rows, colWidths=[80 * mm, 80 * mm])
        t5.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t5)

    # --- Module 9: SIEM sections (only present when the SIEM engine ran) ---
    alerts = data.get("alerts") or []
    incidents = data.get("incidents") or []
    ioc_flat = data.get("ioc_flat") or []
    recommended_controls = data.get("recommended_controls") or []

    if alerts:
        story.append(Paragraph(f"Detected Security Alerts ({len(alerts)})", h2_style))
        rows = [["Severity", "Rule", "MITRE ID", "Confidence", "Risk"]]
        for a in alerts:
            mitre = a.get("mitre") or {}
            rows.append([
                a.get("severity", ""), a.get("rule", ""), mitre.get("technique_id", "N/A"),
                f"{a.get('confidence', 0)}%", str(a.get("risk_score", 0)),
            ])
        t6 = Table(rows, colWidths=[22 * mm, 62 * mm, 26 * mm, 25 * mm, 20 * mm])
        t6.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t6)

        story.append(Paragraph("MITRE ATT&CK Mapping", h2_style))
        seen_techniques = {}
        for a in alerts:
            mitre = a.get("mitre") or {}
            tid = mitre.get("technique_id", "N/A")
            if tid not in seen_techniques:
                seen_techniques[tid] = mitre
        rows = [["Technique", "Tactic", "Description"]]
        for tid, m in seen_techniques.items():
            rows.append([
    Paragraph(f"{tid}: {m.get('technique_name', '')}", body_style),
    Paragraph(m.get("tactic", ""), body_style),
    Paragraph(m.get("description", ""), body_style),
])
        t7 = Table(
    rows,
    colWidths=[45 * mm, 35 * mm, 75 * mm],
    repeatRows=1,
)
        t7.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        story.append(t7)

    if incidents:
        story.append(Paragraph(f"Correlated Incidents ({len(incidents)})", h2_style))
        rows = [["Severity", "Correlated By", "Attack Chain", "Risk"]]
        for i in incidents:
            rows.append([
    Paragraph(i.get("severity", ""), body_style),
    Paragraph(
        f"{i.get('correlated_by','')}: {i.get('correlated_value','')}",
        body_style,
    ),
    Paragraph(i.get("rule_chain", ""), body_style),
    Paragraph(str(i.get("risk_score", 0)), body_style),
])
        t8 = Table(
    rows,
    colWidths=[20 * mm, 45 * mm, 70 * mm, 25 * mm],
    repeatRows=1,
)
        t8.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t8)

    if ioc_flat:
        story.append(Paragraph(f"Indicators of Compromise ({len(ioc_flat)})", h2_style))
        rows = [["Type", "Value", "Attempts", "Failed"]]
        for row in ioc_flat[:25]:
            rows.append([
    Paragraph(str(row["type"]), body_style),
    Paragraph(str(row["value"]), body_style),
    Paragraph(str(row["attempts"]), body_style),
    Paragraph(str(row.get("failed_attempts", 0)), body_style),
])
        t9 = Table(
    rows,
    colWidths=[28 * mm, 72 * mm, 25 * mm, 25 * mm],
    repeatRows=1,
)
        t9.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t9)

    if recommended_controls:
        story.append(Paragraph("Recommendations", h2_style))
        for control in recommended_controls:
            story.append(Paragraph(f"• {control}", body_style))

    # --- Insight ---
    story.append(Paragraph("HawkEye Security Insight", h2_style))
    story.append(Paragraph(data.get("insight", ""), body_style))

    story.append(Spacer(1, 14 * mm))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1"), thickness=1))
    story.append(Paragraph(
        f"Generated by HawkEye Security Solutions &nbsp;|&nbsp; {data.get('analysis_time', '')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8.5,
                       textColor=SLATE, alignment=TA_CENTER, spaceBefore=6),
    ))

    doc.build(story)
    buf.seek(0)
    return buf


def build_csv_report(data):
    """Return a BytesIO buffer containing a CSV export."""
    sio = io.StringIO()
    writer = csv.writer(sio)

    writer.writerow(["HawkEye Security Analysis Report"])
    writer.writerow(["File Name", data.get("filename", "N/A")])
    writer.writerow(["Analysis Time", data.get("analysis_time", "N/A")])
    writer.writerow([])

    writer.writerow(["Summary"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Failed Authentication", data.get("failed", 0)])
    writer.writerow(["Successful Authentication", data.get("success", 0)])
    writer.writerow(["Total Events", data.get("total", 0)])
    writer.writerow(["Risk Level", data.get("risk", "N/A")])
    writer.writerow(["Threat Score", f"{data.get('threat_score', 0)}/100"])
    writer.writerow(["Brute Force Detected", data.get("brute_force", "No")])
    writer.writerow(["Unique Source IPs", data.get("unique_ips", 0)])
    writer.writerow(["Unique Usernames Targeted", data.get("unique_users", 0)])
    writer.writerow([])

    writer.writerow(["Top Suspicious IP Addresses"])
    writer.writerow(["Rank", "IP Address", "Failed Attempts", "Successful Logins"])
    for i, item in enumerate(data.get("top_ips", []), 1):
        writer.writerow([i, item["ip"], item["failed"], item["success"]])
    writer.writerow([])

    writer.writerow(["Username Attack Statistics"])
    writer.writerow(["Rank", "Username", "Failed Attempts"])
    for i, item in enumerate(data.get("top_users", []), 1):
        writer.writerow([i, item["username"], item["attempts"]])
    writer.writerow([])

    if data.get("timeline"):
        writer.writerow(["Attack Timeline"])
        writer.writerow(["Time Bucket", "Failed Attempts"])
        for row in data["timeline"]:
            writer.writerow([row.get("time", ""), row.get("count", 0)])
        writer.writerow([])

    if data.get("alerts"):
        writer.writerow(["Detected Security Alerts"])
        writer.writerow(["Severity", "Rule", "MITRE ID", "MITRE Technique", "Confidence", "Risk Score", "Evidence"])
        for a in data["alerts"]:
            mitre = a.get("mitre") or {}
            writer.writerow([
                a.get("severity", ""), a.get("rule", ""), mitre.get("technique_id", ""),
                mitre.get("technique_name", ""), f"{a.get('confidence', 0)}%",
                a.get("risk_score", 0), " | ".join(a.get("evidence", [])),
            ])
        writer.writerow([])

    if data.get("incidents"):
        writer.writerow(["Correlated Incidents"])
        writer.writerow(["Severity", "Correlated By", "Value", "Attack Chain", "Risk Score"])
        for i in data["incidents"]:
            writer.writerow([
                i.get("severity", ""), i.get("correlated_by", ""), i.get("correlated_value", ""),
                i.get("rule_chain", ""), i.get("risk_score", 0),
            ])
        writer.writerow([])

    if data.get("ioc_flat"):
        writer.writerow(["Indicators of Compromise"])
        writer.writerow(["Type", "Value", "Attempts", "Failed Attempts", "First Seen", "Last Seen"])
        for row in data["ioc_flat"]:
            writer.writerow([
                row["type"], row["value"], row["attempts"], row.get("failed_attempts", 0),
                row.get("first_seen") or "", row.get("last_seen") or "",
            ])
        writer.writerow([])

    if data.get("recommended_controls"):
        writer.writerow(["Recommended Security Controls"])
        for control in data["recommended_controls"]:
            writer.writerow([control])
        writer.writerow([])

    writer.writerow(["Security Insight"])
    writer.writerow([data.get("insight", "")])

    buf = io.BytesIO(sio.getvalue().encode("utf-8-sig"))
    buf.seek(0)
    return buf
