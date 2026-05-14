from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from app.schemas import AnalysisResult


def create_pdf_report(analysis: AnalysisResult) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("GhostTrace Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"File: {analysis.filename}", styles["Normal"]))
    story.append(Paragraph(f"Detected type: {analysis.file_type}", styles["Normal"]))
    story.append(Paragraph(f"Risk level: {analysis.risk.get('severity', 'unknown').title()}", styles["Normal"]))
    story.append(Paragraph(f"Confidence: {analysis.risk.get('confidence', 0)}%", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("AI Analysis Summary", styles["Heading2"]))
    story.append(Paragraph(analysis.ai_summary.replace("\n", "<br/>"), styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Threat Timeline", styles["Heading2"]))
    if analysis.timeline:
        for event in analysis.timeline:
            story.append(Paragraph(f"{event.stage}: {event.details}", styles["BodyText"]))
    else:
        story.append(Paragraph("No timeline events reconstructed.", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Indicators of Compromise", styles["Heading2"]))
    for label, items in analysis.iocs.items():
        story.append(Paragraph(f"{label.title()}: {', '.join(items) if items else 'None detected'}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Technical Findings", styles["Heading2"]))
    story.append(Paragraph(f"Entropy: {analysis.entropy}", styles["BodyText"]))
    story.append(Paragraph(f"Hashes: MD5={analysis.hashes['md5']}, SHA256={analysis.hashes['sha256']}", styles["BodyText"]))
    story.append(Paragraph(f"Suspicious strings: {', '.join(analysis.suspicious_strings) if analysis.suspicious_strings else 'None found'}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommended Actions", styles["Heading2"]))
    for recommendation in analysis.recommendations:
        story.append(Paragraph(f"- {recommendation}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    report_table = Table(
        [["Field", "Value"], ["File Type", analysis.file_type], ["Entropy", str(analysis.entropy)], ["Severity", analysis.risk.get("severity", "unknown")], ["Confidence", f"{analysis.risk.get('confidence', 0)}%"], ["Risk Explanation", analysis.risk.get("explanation", "N/A")]]
    )
    story.append(report_table)

    doc.build(story)
    buffer.seek(0)
    return buffer


def create_url_pdf_report(analysis: dict) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("GhostTrace URL Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"URL: {analysis.get('input_url', '')}", styles["Normal"]))
    story.append(Paragraph(f"Threat level: {analysis.get('threat_level', 'unknown')}", styles["Normal"]))
    story.append(Paragraph(f"Risk score: {analysis.get('risk_score', 0)}", styles["Normal"]))
    story.append(Paragraph(f"Confidence: {analysis.get('confidence', 0)}%", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Threat Explanation", styles["Heading2"]))
    story.append(Paragraph(analysis.get("threat_explanation", "N/A"), styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Security Feedback", styles["Heading2"]))
    feedback = analysis.get("security_feedback", {})
    story.append(Paragraph(f"Severity: {feedback.get('severity_level', analysis.get('threat_level', 'unknown'))}", styles["BodyText"]))
    story.append(Paragraph(f"Confidence: {feedback.get('confidence_score', analysis.get('confidence', 0))}%", styles["BodyText"]))
    story.append(Paragraph(f"Guidance: {' | '.join(feedback.get('what_to_do_next', []))}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings", styles["Heading2"]))
    for finding in analysis.get("findings", []):
        story.append(Paragraph(f"- {finding}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Website Compromise Indicators", styles["Heading2"]))
    for indicator in analysis.get("website_compromise_indicators", []):
        story.append(Paragraph(f"- {indicator}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Extracted Website IOCs", styles["Heading2"]))
    for ioc in analysis.get("iocs", []):
        story.append(Paragraph(f"- {ioc.get('type', 'unknown')}: {ioc.get('value', '')}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Attack Reconstruction", styles["Heading2"]))
    for step in analysis.get("possible_attack_chain", []):
        story.append(Paragraph(f"- {step}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for rec in analysis.get("recommendations", []):
        story.append(Paragraph(f"- {rec}", styles["BodyText"]))
    doc.build(story)
    buffer.seek(0)
    return buffer


def create_log_pdf_report(log_analysis: dict) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("GhostTrace Log Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Threat level: {log_analysis.get('threat_level', 'unknown')}", styles["Normal"]))
    story.append(Paragraph(f"Risk score: {log_analysis.get('risk_score', 0)}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Behavior Patterns", styles["Heading2"]))
    for pattern in log_analysis.get("behavior_patterns", []):
        story.append(Paragraph(f"- {pattern}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("AI Explanation", styles["Heading2"]))
    story.append(Paragraph(log_analysis.get("ai_explanation", "N/A"), styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Likely Investigation Timeline", styles["Heading2"]))
    timeline = [
        "Initial suspicious activity observed in collected logs.",
        "Execution-related indicators identified from commands and callbacks.",
        "Potential persistence or follow-on actions inferred from behavior patterns.",
    ]
    for step in timeline:
        story.append(Paragraph(f"- {step}", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Extracted IOCs", styles["Heading2"]))
    iocs = log_analysis.get("iocs", {})
    for key, values in iocs.items():
        story.append(Paragraph(f"{key}: {', '.join(values) if values else 'None'}", styles["BodyText"]))
    doc.build(story)
    buffer.seek(0)
    return buffer
