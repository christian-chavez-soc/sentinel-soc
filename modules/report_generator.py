from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

REPORTS_DIR = "C:\\AI\\sentinel\\reports"

COLOR_BG = colors.HexColor("#0f1117")
COLOR_PANEL = colors.HexColor("#161b22")
COLOR_ACCENT = colors.HexColor("#58a6ff")
COLOR_ACCENT2 = colors.HexColor("#79c0ff")
COLOR_RED = colors.HexColor("#f85149")
COLOR_ORANGE = colors.HexColor("#d29922")
COLOR_GREEN = colors.HexColor("#3fb950")
COLOR_BORDER = colors.HexColor("#30363d")
COLOR_TEXT = colors.HexColor("#e6edf3")
COLOR_SUBTEXT = colors.HexColor("#8b949e")
COLOR_BLACK = colors.HexColor("#000000")
COLOR_WHITE = colors.HexColor("#ffffff")

def get_severity_label(score, confidence=0):
    if score >= 200 or confidence >= 0.8: return "CRITICAL"
    if score >= 100 or confidence >= 0.5: return "HIGH"
    if score >= 50  or confidence >= 0.3: return "MEDIUM"
    return "LOW"

def generate_report(event_history, agent_registry, response_log, geo_locations):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{REPORTS_DIR}\\sentinel_report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("Title", parent=styles["Title"],
        fontSize=22, textColor=COLOR_BLACK, spaceAfter=4,
        alignment=TA_CENTER, fontName="Helvetica-Bold")

    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"],
        fontSize=9, textColor=COLOR_BLACK, spaceAfter=16, alignment=TA_CENTER)

    section_style = ParagraphStyle("Section", parent=styles["Heading1"],
        fontSize=12, textColor=COLOR_ACCENT2, spaceBefore=14,
        spaceAfter=6, fontName="Helvetica-Bold")

    normal_style = ParagraphStyle("Normal2", parent=styles["Normal"],
        fontSize=9, textColor=COLOR_BLACK, spaceAfter=4)

    elements = []

    # Header
    elements.append(Paragraph("SENTINEL SOC", title_style))
    elements.append(Paragraph("Incident Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Classification: CONFIDENTIAL",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER))
    elements.append(Spacer(1, 10))

    # Executive Summary
    elements.append(Paragraph("Executive Summary", section_style))

    critical_events = [e for e in event_history if e.get("risk_score", 0) >= 200]
    high_events = [e for e in event_history if 100 <= e.get("risk_score", 0) < 200]
    users = set(e.get("username") for e in event_history)

    summary_data = [
        ["Metric", "Value"],
        ["Total Events Detected", str(len(event_history))],
        ["Critical Alerts", str(len(critical_events))],
        ["High Alerts", str(len(high_events))],
        ["Users Monitored", str(len(users))],
        ["Automated Responses", str(len(response_log))],
        ["Connected Agents", str(len(agent_registry))],
        ["Geo Locations Tracked", str(len(geo_locations))],
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    ]

    summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_ACCENT2),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BACKGROUND", (0, 1), (-1, -1), COLOR_BG),
        ("TEXTCOLOR", (0, 1), (0, -1), COLOR_SUBTEXT),
        ("TEXTCOLOR", (1, 1), (1, -1), COLOR_TEXT),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_BG, COLOR_PANEL]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # Critical Alerts
    elements.append(Paragraph("Critical & High Alerts", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    alert_events = [e for e in event_history if e.get("risk_score", 0) >= 100]
    if alert_events:
        alert_data = [["User", "Origin", "Risk", "Severity", "Confidence", "Reasons"]]
        for event in sorted(alert_events, key=lambda x: x.get("risk_score", 0), reverse=True)[:20]:
            score = event.get("risk_score", 0)
            confidence = event.get("confidence", 0)
            reasons = ", ".join(event.get("reasons", [])[:3])
            if len(reasons) > 60: reasons = reasons[:60] + "..."
            alert_data.append([
                event.get("username", "unknown"),
                event.get("origin", "unknown"),
                str(score),
                get_severity_label(score, confidence),
                str(round(confidence, 2)),
                reasons
            ])
        alert_table = Table(alert_data, colWidths=[1*inch, 1.2*inch, 0.6*inch, 0.8*inch, 0.8*inch, 2.6*inch])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_ACCENT2),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), COLOR_BG),
            ("TEXTCOLOR", (0, 1), (-1, -1), COLOR_TEXT),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_BG, COLOR_PANEL]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No critical or high alerts recorded.", normal_style))

    elements.append(Spacer(1, 10))

    # Connected Agents
    elements.append(Paragraph("Connected Agents", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    if agent_registry:
        agent_data = [["Agent Host", "OS", "Last Seen", "Events Processed"]]
        for agent in agent_registry.values():
            agent_data.append([
                agent.get("host", "unknown"),
                agent.get("os", "unknown"),
                agent.get("last_seen", "unknown")[:19] if agent.get("last_seen") else "unknown",
                str(agent.get("event_count", 0))
            ])
        agent_table = Table(agent_data, colWidths=[2*inch, 1*inch, 2.5*inch, 1.5*inch])
        agent_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_ACCENT2),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BACKGROUND", (0, 1), (-1, -1), COLOR_BG),
            ("TEXTCOLOR", (0, 1), (-1, -1), COLOR_TEXT),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_BG, COLOR_PANEL]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(agent_table)

    elements.append(Spacer(1, 10))

    # Geo Locations
    elements.append(Paragraph("Attack Origin Intelligence", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    if geo_locations:
        geo_data = [["Username", "IP Address", "City", "Country", "Risk Score"]]
        for loc in sorted(geo_locations, key=lambda x: x.get("risk_score", 0), reverse=True)[:15]:
            geo_data.append([
                loc.get("username", "unknown"),
                loc.get("ip", "unknown"),
                loc.get("city", "unknown"),
                loc.get("country", "unknown"),
                str(loc.get("risk_score", 0))
            ])
        geo_table = Table(geo_data, colWidths=[1.2*inch, 1.3*inch, 1.3*inch, 1.5*inch, 1.7*inch])
        geo_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_ACCENT2),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BACKGROUND", (0, 1), (-1, -1), COLOR_BG),
            ("TEXTCOLOR", (0, 1), (-1, -1), COLOR_TEXT),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_BG, COLOR_PANEL]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(geo_table)

    elements.append(Spacer(1, 10))

    # Automated Responses
    elements.append(Paragraph("Automated Responses Taken", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    if response_log:
        resp_data = [["Action", "Target", "Status", "Detail"]]
        for resp in response_log[:20]:
            detail = resp.get("detail", "")[:50]
            resp_data.append([
                resp.get("action", "unknown"),
                resp.get("target", "unknown"),
                "OK" if resp.get("success") else "FAILED",
                detail
            ])
        resp_table = Table(resp_data, colWidths=[1.3*inch, 1.3*inch, 0.7*inch, 3.7*inch])
        resp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PANEL),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_ACCENT2),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BACKGROUND", (0, 1), (-1, -1), COLOR_BG),
            ("TEXTCOLOR", (0, 1), (-1, -1), COLOR_TEXT),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_BG, COLOR_PANEL]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(resp_table)

    elements.append(Spacer(1, 10))

    # Recommendations
    elements.append(Paragraph("Recommendations", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    recommendations = []
    if critical_events:
        recommendations.append("Immediately investigate and isolate affected hosts from critical alert events.")
    if any("lateral" in str(e.get("reasons", "")).lower() for e in event_history):
        recommendations.append("Lateral movement detected - conduct full network sweep and review all privileged account activity.")
    if any("brute" in str(e.get("reasons", "")).lower() or "failed" in str(e.get("reasons", "")).lower() for e in event_history):
        recommendations.append("Brute force activity detected - enforce account lockout policies and enable MFA.")
    if geo_locations:
        recommendations.append("External IP addresses detected - review firewall rules and consider geo-blocking high risk countries.")
    if any("privilege" in str(e.get("reasons", "")).lower() for e in event_history):
        recommendations.append("Privileged account abuse detected - audit administrator account usage and implement PAM solution.")
    recommendations.append("Review all automated response actions taken and verify their effectiveness.")
    recommendations.append("Update threat intelligence feeds and review detection rules based on this incident.")

    for i, rec in enumerate(recommendations, 1):
        elements.append(Paragraph(f"{i}.  {rec}", normal_style))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 6))

    footer_style = ParagraphStyle("Footer", parent=styles["Normal"],
        fontSize=9, textColor=COLOR_BLACK, alignment=TA_CENTER)
    elements.append(Paragraph(
        f"Sentinel SOC Platform  |  Report ID: {timestamp}  |  Confidential",
        footer_style
    ))

    doc.build(elements)
    print(f"REPORT GENERATED: {filename}")
    return filename
