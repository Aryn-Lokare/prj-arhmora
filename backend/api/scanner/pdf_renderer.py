import os
from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

def add_header_footer(canvas, doc):
    canvas.saveState()
    
    # Paths
    base_dir = str(settings.BASE_DIR)
    logo_path = os.path.join(base_dir, "..", "frontend", "public", "Group 17.png")
    logo_path = os.path.abspath(logo_path)
    
    # Header (Logo only, brand text removed as per task 1)
    if os.path.exists(logo_path):
        try:
            canvas.drawImage(logo_path, 50, A4[1]-55, width=0.5*inch, height=0.5*inch, mask='auto', preserveAspectRatio=True)
        except Exception:
            pass
    
    # Footer
    canvas.setFont('Helvetica', 9)
    canvas.setStrokeColor(colors.lightgrey)
    canvas.line(50, 40, A4[0]-50, 40)
    canvas.setFillColor(colors.grey)
    canvas.drawString(50, 30, "ARMORA Security Intelligence - Confidential")
    canvas.drawRightString(A4[0]-50, 30, f"Page {doc.page}")
    
    canvas.restoreState()

def render_report_to_pdf(report_data: dict, output_path: str):
    """
    Generates a professional security report PDF using ReportLab with premium styling.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=55,
        leftMargin=55,
        topMargin=65,
        bottomMargin=65
    )
    
    styles = getSampleStyleSheet()
    
    # Updated Typography System (Mandatory Task 2)
    styles.add(ParagraphStyle(
        name='PremiumTitle',
        fontSize=30,
        leading=36,
        spaceAfter=20,
        textColor=colors.HexColor('#1A2B4C'),
        fontName='Helvetica-Bold',
        alignment=0,
        letterSpacing=1
    ))
    
    styles.add(ParagraphStyle(
        name='MainSectionHeader',
        fontSize=19,
        leading=24,
        spaceBefore=20,
        spaceAfter=25,
        textColor=colors.HexColor('#1A2B4C'),
        fontName='Helvetica-Bold',
    ))

    styles.add(ParagraphStyle(
        name='SubSectionHeader',
        fontSize=15,
        leading=20,
        spaceBefore=15,
        spaceAfter=12,
        textColor=colors.HexColor('#2E3A59'),
        fontName='Helvetica-Bold'
    ))

    # Task 4: Executive Summary Box
    styles.add(ParagraphStyle(
        name='ExecSummaryBox',
        fontSize=11.5,
        leading=17,
        fontName='Helvetica',
        textColor=colors.HexColor('#333333'),
        backColor=colors.HexColor('#F5F7FA'),
        borderPadding=18,
        borderRadius=4,
        spaceBefore=15,
        spaceAfter=20
    ))

    # Body Text Upgrade
    report_body_style = ParagraphStyle(
        name='ReportBody',
        parent=styles['Normal'],
        fontSize=11.5,
        leading=17,
        textColor=colors.HexColor('#333333'),
        fontName='Helvetica',
        spaceAfter=12,
        alignment=0 # Left aligned
    )
    styles.add(report_body_style)

    # Metadata Style
    styles.add(ParagraphStyle(
        name='ReportMetadata',
        parent=styles['Normal'],
        fontSize=10.5,
        textColor=colors.HexColor('#555555'),
        fontName='Helvetica',
        leading=14
    ))

    # Severity Badge Style (Task 5)
    styles.add(ParagraphStyle(
        name='SeverityBadge',
        fontSize=9,
        leading=12,
        textColor=colors.white,
        borderPadding=(3, 6, 3, 6),
        borderRadius=2,
        alignment=1,
        fontName='Helvetica-Bold'
    ))

    # --- KEEPING UNTOUCHED AS PER CRITICAL CONSTRAINT ---
    styles.add(ParagraphStyle(
        name='ImpactHeader',
        fontSize=13,
        leading=16,
        spaceBefore=25,
        spaceAfter=22,
        textColor=colors.HexColor('#311b92'),
        fontName='Helvetica-Bold',
        textTransform='uppercase'
    ))

    styles.add(ParagraphStyle(
        name='ImpactBox',
        fontSize=11,
        leading=16,
        leftIndent=10,
        rightIndent=10,
        spaceBefore=10,
        fontName='Helvetica-Oblique',
        textColor=colors.HexColor('#1a1a1a'),
        backColor=colors.HexColor('#f5f0ff'),
        borderPadding=15,
        borderRadius=8
    ))

    story = []

    # --- Cover Page ---
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("SECURITY AUDIT REPORT", styles['PremiumTitle']))
    story.append(Paragraph(f"Analysis for: {report_data.get('target_url')}", styles['SubSectionHeader']))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a237e'), spaceBefore=20, spaceAfter=20))
    story.append(Spacer(1, 0.5 * inch))
    
    meta_data = [
        [Paragraph("Status: CONFIDENTIAL", styles['ReportMetadata']), ""],
        [Paragraph(f"Report ID: ARM-{os.path.basename(output_path).split('_')[2]}", styles['ReportMetadata']), ""],
        [Paragraph(f"Generated on: {report_data.get('timestamp')}", styles['ReportMetadata']), ""],
    ]
    t = Table(meta_data, colWidths=[3.5*inch, 2*inch])
    t.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(PageBreak())

    # --- Executive Summary (Refined spacing & boxed layout) ---
    story.append(Paragraph("1. Executive Summary", styles['MainSectionHeader']))
    story.append(Paragraph(report_data.get('executive_summary', ''), styles['ExecSummaryBox']))
    
    story.append(Paragraph("2. Risk Assessment Summary", styles['MainSectionHeader']))
    story.append(Paragraph(report_data.get('overall_risk_analysis', ''), styles['ReportBody']))
    story.append(PageBreak())

    # --- Vulnerabilities ---
    story.append(Paragraph("3. Detailed Vulnerability Analysis", styles['MainSectionHeader']))
    story.append(Spacer(1, 10))
    
    findings = report_data.get('vulnerabilities', [])
    for idx, v in enumerate(findings):
        # Task 5: Severity Colors & Badges
        severity = v.get('severity', 'UNKNOWN').upper()
        sev_color = colors.HexColor('#D64545') if severity == 'HIGH' else \
                    colors.HexColor('#F39C12') if severity == 'MEDIUM' else \
                    colors.HexColor('#3498DB')
        
        # 3.x Clean Title Layout
        story.append(Paragraph(f"3.{idx+1} {v.get('title', 'Unknown Finding')}", styles['SubSectionHeader']))
        
        # Severity Badge - Compact Layout Fix
        # Using a small Table as a wrapper to prevent full-width background bar
        tg_data = [[Paragraph(f"<b>{severity}</b>", styles['SeverityBadge'])]]
        tg = Table(tg_data, colWidths=[100])
        tg.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), sev_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(tg)
        story.append(Spacer(1, 14))
        
        # Technical Analysis
        story.append(Paragraph("Technical Analysis", styles['SubSectionHeader']))
        story.append(Paragraph(v.get('technical_explanation', ''), styles['ReportBody']))
        
        story.append(Paragraph("Exploitation Risk", styles['SubSectionHeader']))
        story.append(Paragraph(v.get('risk_analysis', ''), styles['ReportBody']))
        story.append(Spacer(1, 10))
        
        # Business Impact - UNTOUCHED CONSTRAINT
        story.append(Paragraph("BUSINESS IMPACT (FOR EXECUTIVES)", styles['ImpactHeader']))
        story.append(Paragraph(v.get('business_impact', 'N/A'), styles['ImpactBox']))
        story.append(Spacer(1, 20))
        
        # Remediation Plan - Structured Bullet List
        story.append(Paragraph("Remediation Plan", styles['SubSectionHeader']))
        remediation = v.get('remediation', '')
        
        if '\n' in remediation or (remediation.count('.') > 1):
            steps = [s.strip() for s in remediation.split('\n') if s.strip()]
            for step in steps:
                if step:
                    story.append(Paragraph(f"• {step}", styles['ReportBody']))
        else:
            story.append(Paragraph(remediation, styles['ReportBody']))
        
        # Visual Simplification (Remove heavy divider lines)
        if idx < len(findings) - 1:
            story.append(Spacer(1, 40))
            if severity == 'HIGH':
                story.append(PageBreak())

    # doc.build supports onFirstPage and onLaterPages hooks for header/footer
    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    return True
