from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    HRFlowable
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from io import BytesIO
from datetime import datetime
import os

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    HRFlowable
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime
import os


def add_page_decorations(canvas, doc):
    width, height = A4

    # -------- PAGE BORDER --------
    canvas.saveState()
    canvas.setLineWidth(1)
    canvas.rect(20, 20, width - 40, height - 40)

    # -------- WATERMARK --------
    canvas.setFont("Helvetica-Bold", 60)
    canvas.setFillGray(0.9, 0.3)
    canvas.drawCentredString(
        width / 2,
        height / 2,
        "ARHMORA CONFIDENTIAL"
    )

    # -------- FOOTER --------
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.black)

    canvas.drawString(
        40,
        30,
        "Confidential – Arhmora Security"
    )

    # -------- PAGE NUMBER --------
    page_number_text = f"Page {doc.page}"
    canvas.drawRightString(
        width - 40,
        30,
        page_number_text
    )

    canvas.restoreState()

def generate_pdf_report(scan):

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        spaceBefore=12,
        alignment=1  # center
    )

    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=10,
        spaceAfter=6
    )

    normal_bold = ParagraphStyle(
        'NormalBold',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=4
    )

    # -------------------------
    # LOGO
    # -------------------------
    logo_path = os.path.join(
        os.path.dirname(__file__),
        "arhmora_logo.png"
    )

    if os.path.exists(logo_path):
        logo = Image(logo_path, width=2.5 * inch, height=1 * inch)
        logo.hAlign = "CENTER"
        elements.append(logo)
        elements.append(Spacer(1, 20))

    # -------------------------
    # TITLE
    # -------------------------
    elements.append(Paragraph("<b>ARHMORA SECURITY REPORT</b>", title_style))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 12))

    # -------------------------
    # BASIC INFO
    # -------------------------
    findings = scan.findings.all()

    high_count = findings.filter(severity="High").count()
    medium_count = findings.filter(severity="Medium").count()
    low_count = findings.filter(severity="Low").count()

    overall_risk = scan.overall_risk_score if hasattr(scan, "overall_risk_score") else 0

    elements.append(Paragraph(f"<b>Target:</b> {scan.target_url}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan.id}", styles["Normal"]))
    elements.append(Paragraph(
        f"<b>Date:</b> {datetime.now().strftime('%d %b %Y')}",
        styles["Normal"]
    ))
    elements.append(Paragraph(
        f"<b>Overall Risk Score:</b> {overall_risk}/100",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 10))

    # -------------------------
    # EXECUTIVE SUMMARY
    # -------------------------
    elements.append(Paragraph("<b>EXECUTIVE SUMMARY</b>", section_style))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 8))

    summary_text = (
        "This report provides a structured analysis of the target system. "
        "Multiple vulnerabilities were identified which may pose security risks. "
        "Immediate attention is recommended for high-severity findings."
    )

    elements.append(Paragraph(summary_text, styles["Normal"]))
    elements.append(Spacer(1, 15))

    # -------------------------
    # VULNERABILITY SUMMARY
    # -------------------------
    elements.append(Paragraph("<b>VULNERABILITY SUMMARY</b>", section_style))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph(f"<b>High:</b> {high_count}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Medium:</b> {medium_count}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Low:</b> {low_count}", styles["Normal"]))

    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 10))

    # -------------------------
    # DETAILED FINDINGS
    # -------------------------
    elements.append(Paragraph("<b>DETAILED FINDINGS</b>", section_style))
    elements.append(HRFlowable(width="100%"))
    elements.append(Spacer(1, 12))

    for finding in findings:

        elements.append(
            Paragraph(
                f"<b>[ {finding.severity.upper()} ] {finding.v_type}</b>",
                styles["Normal"]
            )
        )
        elements.append(Spacer(1, 6))

        elements.append(
            Paragraph(f"<b>Risk Score:</b> {finding.risk_score}", styles["Normal"])
        )
        elements.append(
            Paragraph(f"<b>Confidence:</b> {finding.total_confidence}%", styles["Normal"])
        )

        elements.append(Spacer(1, 8))

        elements.append(Paragraph("<b>Description:</b>", styles["Normal"]))
        elements.append(Paragraph(finding.evidence, styles["Normal"]))

        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Impact:</b>", styles["Normal"]))
        elements.append(Paragraph("Potential compromise of system security.", styles["Normal"]))

        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Remediation:</b>", styles["Normal"]))
        elements.append(Paragraph(finding.remediation, styles["Normal"]))

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%"))
        elements.append(Spacer(1, 15))

    # Build document
    doc.build(
    elements,
    onFirstPage=add_page_decorations,
    onLaterPages=add_page_decorations
)


    buffer.seek(0)
    return buffer
