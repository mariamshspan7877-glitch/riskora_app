import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def create_pdf_report(assessment, user, report_path):
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    doc = SimpleDocTemplate(report_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#7C3AED"), fontSize=20)
    heading_style = ParagraphStyle("HeadingStyle", parent=styles["Heading2"], textColor=colors.HexColor("#C084FC"))
    body_style = ParagraphStyle("BodyStyle", parent=styles["BodyText"], fontSize=10, leading=14)
    story = []

    story.append(Paragraph("Riskora", title_style))
    story.append(Paragraph("Cloud-Based File Security and Risk Assessment Platform", heading_style))
    story.append(Spacer(1, 16))
    story.append(Paragraph(f"Assessment ID: {assessment.id}", body_style))
    story.append(Paragraph(f"Prepared for: {user.full_name}", body_style))
    story.append(Paragraph(f"Date: {assessment.created_at.strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Paragraph(f"Risk Score: {assessment.risk_score} ({assessment.risk_label})", body_style))
    story.append(Spacer(1, 16))

    data = [
        ["Field", "Value"],
        ["Original file name", assessment.original_name],
        ["Stored file name", assessment.filename],
        ["File type", assessment.file_type],
        ["Size (bytes)", str(assessment.file_size)],
        ["SHA-256", assessment.sha256],
        ["Status", assessment.status],
        ["Cloud upload", assessment.upload_status],
    ]
    table = Table(data, colWidths=[180, 320])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7C3AED")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8ACD6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F3FF"), colors.HexColor("#E9D5FF")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 18))
    story.append(Paragraph("Findings", heading_style))

    for finding in assessment.findings:
        story.append(Paragraph(f"{finding.title} ({finding.severity.upper()})", body_style))
        story.append(Paragraph(f"Description: {finding.description}", body_style))
        story.append(Paragraph(f"Evidence: {finding.evidence or 'Not supplied'}", body_style))
        story.append(Paragraph(f"Mitigation: {finding.remediation or 'Review and remediate as appropriate'}", body_style))
        story.append(Spacer(1, 10))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Assessment limitations: This project-defined score is intended for educational and risk-awareness use and does not guarantee a real malware determination.", body_style))
    doc.build(story)
