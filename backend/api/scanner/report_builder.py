import os
import logging
from django.conf import settings
from api.models import ScanHistory
from .ai_content_generator import generate_structured_intelligence
from .pdf_renderer import render_report_to_pdf

logger = logging.getLogger(__name__)

def generate_ai_report_option_a(scan_id):
    """
    Orchestrate Option A PDF generation:
    1. Fetch findings
    2. Generate AI JSON
    3. Render PDF with ReportLab
    """
    try:
        scan = ScanHistory.objects.get(id=scan_id)
    except ScanHistory.DoesNotExist:
        return None, "Scan not found."

    # Relaxed filter: include both confirmed and likely vulnerabilities for a more complete report
    findings = scan.findings.filter(classification__in=['confirmed', 'likely'])
    
    # We now allow report generation even if no findings exist, providing a "Clean Perimeter" report
    # instead of strictly failing with 400.

    # Prepare metadata
    scan_metadata = {
        'target_url': scan.target_url,
        'timestamp': scan.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'findings': [
            {
                'v_type': f.v_type,
                'severity': f.severity,
                'affected_url': f.affected_url,
                'explanation_technical': f.explanation_technical,
                'remediation_technical': f.remediation_technical,
            } for f in findings
        ]
    }
    # Build severity lookup so the renderer can access it after AI merge
    _severity_by_type = {f.v_type: f.severity for f in findings}

    # 1. Get AI Intelligence - If no findings, we can skip LLM or send a summary prompt
    if findings.exists():
        ai_data = generate_structured_intelligence(scan_metadata)
    else:
        ai_data = {
            "executive_summary": "Security perimeter analysis completed. No critical or likely vulnerabilities were identified during this automated assessment.",
            "overall_risk_analysis": "The target infrastructure demonstrates a strong security posture against the tested exploit vectors.",
            "vulnerabilities": []
        }
    
    # 2. Merge data for builder
    full_report_data = {**scan_metadata, **ai_data}
    # Inject severity into AI-generated vulnerability entries
    for vuln in full_report_data.get('vulnerabilities', []):
        if 'severity' not in vuln:
            vuln['severity'] = _severity_by_type.get(vuln.get('title', ''), 'MEDIUM')
    
    # 3. Setup paths
    base_dir = str(settings.BASE_DIR)
    media_root = str(getattr(settings, 'MEDIA_ROOT', os.path.join(base_dir, 'media')))
    reports_dir = os.path.join(media_root, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = f"ARMORA_Intelligence_{scan.id}_{scan.timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(reports_dir, filename)
    
    # 4. Render
    try:
        success = render_report_to_pdf(full_report_data, output_path)
        if success:
            return output_path, None
        return None, "PDF rendering failed."
    except Exception as e:
        logger.exception(f"Report construction failed: {e}")
        return None, f"Report builder error: {str(e)}"
