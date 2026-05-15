from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from app.schemas import UnifiedInvestigationResult


def _sev_color(severity: str):
    s = (severity or "").lower()
    if s == "critical": return colors.HexColor("#ff2d55")
    if s == "high":     return colors.HexColor("#ffaa00")
    if s == "medium":   return colors.HexColor("#3b82f6")
    if s in ("low", "clean"): return colors.HexColor("#00ff88")
    return colors.HexColor("#8e8e93")


def _build_styles() -> dict:
    styles = getSampleStyleSheet()
    defs = [
        ParagraphStyle("GT_Title",  parent=styles["Title"],    fontSize=22, textColor=colors.HexColor("#00ff88"), spaceAfter=6),
        ParagraphStyle("GT_Sub",    parent=styles["Normal"],   fontSize=11, textColor=colors.HexColor("#8e8e93"), spaceAfter=10),
        ParagraphStyle("GT_Header", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#00d4ff"),
                       backColor=colors.HexColor("#0c1018"), borderPadding=5, spaceBefore=14, spaceAfter=8),
        ParagraphStyle("GT_Label",  parent=styles["Normal"],   fontSize=9,  textColor=colors.HexColor("#7a8fa8"), fontName="Helvetica-Bold"),
        ParagraphStyle("GT_Value",  parent=styles["Normal"],   fontSize=9,  textColor=colors.HexColor("#e8edf5")),
        ParagraphStyle("GT_Body",   parent=styles["Normal"],   fontSize=9,  leading=14, textColor=colors.HexColor("#e8edf5")),
        ParagraphStyle("GT_Mono",   parent=styles["Normal"],   fontSize=8,  leading=13, fontName="Courier", textColor=colors.HexColor("#8fb08c")),
        ParagraphStyle("GT_Footer", parent=styles["Normal"],   fontSize=7,  textColor=colors.HexColor("#3d5068"), alignment=1),
    ]
    for ps in defs:
        if ps.name not in styles.byName:
            styles.add(ps)
    return styles


def _table_style(header: bool = False):
    base = [
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0c1018")),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#1e2d40")),
        ("PADDING",    (0, 0), (-1, -1), 6),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]
    if header:
        base += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a1520")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#00d4ff")),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    return TableStyle(base)


def _story_header(story, styles, title: str, subtitle: str, report_type: str = ""):
    story.append(Paragraph("GHOSTTRACE", styles["GT_Title"]))
    story.append(Paragraph(title, styles["GT_Sub"]))
    story.append(Paragraph(
        f"Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}   |   Type: {report_type.upper() or 'UNIFIED'}",
        styles["GT_Footer"]
    ))
    story.append(Spacer(1, 14))


def _summary_table(styles, result: UnifiedInvestigationResult) -> Table:
    sc = _sev_color(result.severity)
    sev_style = ParagraphStyle("_Sev", parent=styles["GT_Value"], textColor=sc, fontName="Helvetica-Bold")
    rows = [
        [Paragraph("TARGET", styles["GT_Label"]),    Paragraph(str(result.target), styles["GT_Value"])],
        [Paragraph("TYPE",   styles["GT_Label"]),    Paragraph(str(result.type).upper(), styles["GT_Value"])],
        [Paragraph("SEVERITY", styles["GT_Label"]),  Paragraph(str(result.severity).upper(), sev_style)],
        [Paragraph("RISK SCORE", styles["GT_Label"]), Paragraph(f"{result.risk_score}/100", styles["GT_Value"])],
        [Paragraph("CONFIDENCE", styles["GT_Label"]), Paragraph(f"{result.confidence}%", styles["GT_Value"])],
        [Paragraph("IOCs FOUND", styles["GT_Label"]), Paragraph(str(len(result.iocs or [])), styles["GT_Value"])],
    ]
    t = Table(rows, colWidths=[1.4*inch, 5.1*inch])
    t.setStyle(_table_style())
    return t


def _ioc_section(story, styles, iocs: list):
    story.append(Paragraph("INDICATORS OF COMPROMISE (IOCs)", styles["GT_Header"]))
    if not iocs:
        story.append(Paragraph("No IOCs extracted.", styles["GT_Body"]))
        return
    rows = [["TYPE", "VALUE"]]
    for ioc in iocs:
        rows.append([
            str(ioc.get("type", "unknown")).upper(),
            str(ioc.get("value", "")),
        ])
    t = Table(rows, colWidths=[1.2*inch, 5.3*inch])
    t.setStyle(_table_style(header=True))
    story.append(t)
    story.append(Spacer(1, 10))


def _timeline_section(story, styles, timeline: list):
    story.append(Paragraph("INVESTIGATION TIMELINE", styles["GT_Header"]))
    if not timeline:
        story.append(Paragraph("No timeline events recorded.", styles["GT_Body"]))
        return
    rows = [["STAGE", "DETAILS", "SEV"]]
    for ev in timeline:
        rows.append([
            str(ev.get("stage", "")),
            str(ev.get("details", "")),
            str(ev.get("sev", "low")).upper(),
        ])
    t = Table(rows, colWidths=[1.4*inch, 4.0*inch, 0.6*inch])
    t.setStyle(_table_style(header=True))
    story.append(t)
    story.append(Spacer(1, 10))


def _mitre_section(story, styles, mitre: list):
    if not mitre:
        return
    story.append(Paragraph("MITRE ATT&CK® MAPPING", styles["GT_Header"]))
    rows = [["TECHNIQUE ID", "TECHNIQUE NAME"]]
    for m in mitre:
        rows.append([str(m.get("id", "")), str(m.get("technique", ""))])
    t = Table(rows, colWidths=[1.4*inch, 5.1*inch])
    t.setStyle(_table_style(header=True))
    story.append(t)
    story.append(Spacer(1, 10))


def _recs_section(story, styles, recs: list):
    story.append(Paragraph("REMEDIATION & RECOMMENDATIONS", styles["GT_Header"]))
    if not recs:
        story.append(Paragraph("No specific recommendations generated.", styles["GT_Body"]))
        return
    for rec in recs:
        story.append(Paragraph(f"<b>•</b> {rec}", styles["GT_Body"]))


def create_unified_pdf_report(result: UnifiedInvestigationResult) -> BytesIO:
    """Single unified report builder for all scan types (file, url, log)."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.5*inch, rightMargin=0.5*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch
    )
    styles = _build_styles()
    story = []

    _story_header(story, styles,
                  f"Forensic Investigation Report — {result.target}",
                  "GhostTrace AI-Powered Threat Analysis Platform",
                  result.type)

    story.append(_summary_table(styles, result))
    story.append(Spacer(1, 16))

    # AI explanation
    story.append(Paragraph("AI THREAT ANALYSIS", styles["GT_Header"]))
    ai_text = (result.ai_explanation or "No AI explanation available.").replace("\n", "<br/>")
    story.append(Paragraph(ai_text, styles["GT_Mono"]))
    story.append(Spacer(1, 10))

    # Raw artifacts block (file-specific)
    if result.raw_artifacts:
        artifacts = result.raw_artifacts
        if artifacts.get("hashes") or artifacts.get("entropy") is not None:
            story.append(Paragraph("FILE FORENSICS", styles["GT_Header"]))
            hashes = artifacts.get("hashes", {})
            file_rows = []
            if artifacts.get("entropy") is not None:
                file_rows.append(["ENTROPY", str(artifacts["entropy"])])
            if hashes.get("md5"):
                file_rows.append(["MD5", hashes["md5"]])
            if hashes.get("sha256"):
                file_rows.append(["SHA256", hashes["sha256"]])
            if hashes.get("sha1"):
                file_rows.append(["SHA1", hashes["sha1"]])
            yara = artifacts.get("yara_matches", [])
            if yara:
                file_rows.append(["YARA MATCHES", ", ".join(yara[:10])])
            if file_rows:
                ft = Table(file_rows, colWidths=[1.4*inch, 5.1*inch])
                ft.setStyle(_table_style())
                story.append(ft)
            story.append(Spacer(1, 10))

        # URL / page artifacts
        page = artifacts.get("page_artifacts", {})
        if page.get("available"):
            story.append(Paragraph("PAGE ARTIFACTS", styles["GT_Header"]))
            page_rows = [
                ["TITLE",           str(page.get("title") or "N/A")],
                ["SCRIPTS",         str(page.get("script_count", 0))],
                ["IFRAMES",         str(page.get("iframe_count", 0))],
                ["HIDDEN IFRAMES",  str(page.get("hidden_iframe_count", 0))],
                ["SUSPICIOUS FORMS", str(page.get("suspicious_form_count", 0))],
            ]
            pt = Table(page_rows, colWidths=[1.4*inch, 5.1*inch])
            pt.setStyle(_table_style())
            story.append(pt)
            story.append(Spacer(1, 10))

        # Log behavior patterns
        patterns = artifacts.get("behavior_patterns", [])
        if patterns:
            story.append(Paragraph("BEHAVIORAL PATTERNS DETECTED", styles["GT_Header"]))
            for p in patterns:
                story.append(Paragraph(f"<b>•</b> {p}", styles["GT_Body"]))
            story.append(Spacer(1, 10))

    _ioc_section(story, styles, result.iocs or [])
    _timeline_section(story, styles, result.timeline or [])
    _mitre_section(story, styles, result.mitre_mapping or [])
    _recs_section(story, styles, result.recommendations or [])

    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "GhostTrace — AI-Powered Malware &amp; Threat Intelligence Platform | For authorized investigation use only.",
        styles["GT_Footer"]
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


# ── Backwards-compatible shims ─────────────────────────────────────────────

def create_pdf_report(analysis: UnifiedInvestigationResult) -> BytesIO:
    """File scan report — delegates to unified builder."""
    return create_unified_pdf_report(analysis)


def create_url_pdf_report(analysis) -> BytesIO:
    """URL scan report — accepts UnifiedInvestigationResult OR legacy dict."""
    if isinstance(analysis, dict):
        # Convert legacy dict to UnifiedInvestigationResult
        from app.schemas import UnifiedInvestigationResult as UIR
        iocs = analysis.get("iocs", [])
        if isinstance(iocs, dict):
            flat = []
            for k, vals in iocs.items():
                if isinstance(vals, list):
                    for v in vals:
                        flat.append({"type": k.rstrip("s"), "value": str(v)})
            iocs = flat
        timeline = analysis.get("timeline", [])
        if isinstance(timeline, list) and timeline and isinstance(timeline[0], str):
            timeline = [{"stage": t, "details": "", "sev": "low"} for t in timeline]
        result = UIR(
            target=analysis.get("input_url") or analysis.get("target") or "Unknown URL",
            type="url",
            risk_score=int(analysis.get("risk_score", 0)),
            severity=str(analysis.get("threat_level") or analysis.get("severity", "unknown")),
            confidence=int(analysis.get("confidence", 0)),
            iocs=iocs,
            timeline=timeline,
            ai_explanation=str(analysis.get("threat_explanation") or analysis.get("ai_explanation", "")),
            recommendations=analysis.get("recommendations", []),
            mitre_mapping=analysis.get("mitre_mapping", []),
            raw_artifacts={
                "page_artifacts": analysis.get("page_artifacts", {}),
                "ssl_info": analysis.get("reputation_signals", {}).get("ssl_certificate_analysis", {}),
            },
        )
        return create_unified_pdf_report(result)
    return create_unified_pdf_report(analysis)


def create_log_pdf_report(log_analysis) -> BytesIO:
    """Log analysis report — accepts UnifiedInvestigationResult OR legacy dict."""
    if isinstance(log_analysis, dict):
        from app.schemas import UnifiedInvestigationResult as UIR
        iocs = log_analysis.get("iocs", {})
        flat_iocs = []
        if isinstance(iocs, dict):
            for k, vals in iocs.items():
                if isinstance(vals, list):
                    for v in vals:
                        flat_iocs.append({"type": k.rstrip("s"), "value": str(v)})
        elif isinstance(iocs, list):
            flat_iocs = iocs
        result = UIR(
            target="System Logs",
            type="log",
            risk_score=int(log_analysis.get("risk_score", 0)),
            severity=str(log_analysis.get("threat_level") or log_analysis.get("severity", "unknown")),
            confidence=int(log_analysis.get("confidence", 0)),
            iocs=flat_iocs,
            timeline=log_analysis.get("timeline", []),
            ai_explanation=str(log_analysis.get("ai_explanation", "")),
            recommendations=log_analysis.get("recommendations", []),
            raw_artifacts={"behavior_patterns": log_analysis.get("behavior_patterns", [])},
        )
        return create_unified_pdf_report(result)
    return create_unified_pdf_report(log_analysis)
