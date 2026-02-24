# backend/api/scanner/report_service.py

import os
import bleach
import logging
from django.conf import settings
from api.models import ScanHistory, ScanFinding
from .ai_report_generator import generate_html_report
from .pdf_renderer import render_pdf

logger = logging.getLogger(__name__)

# Sanitization Configuration
ALLOWED_TAGS = [
    'html', 'body', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
    'p', 'br', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 
    'ul', 'ol', 'li', 'b', 'strong', 'i', 'em', 'style'
]
ALLOWED_ATTRS = {
    '*': ['style', 'class'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
}

def generate_pdf_report(scan_id):
    """
    Main orchestration function for generating the AI-driven PDF report.
    """
    try:
        scan = ScanHistory.objects.get(id=scan_id)
    except ScanHistory.DoesNotExist:
        return None, "Scan not found."

    # Fetch only confirmed and likely findings
    findings = scan.findings.filter(classification__in=['confirmed', 'likely'])
    
    if not findings.exists():
        return None, "No significant vulnerabilities (Confirmed or Likely) found to generate a report."

    # Prepare data for AI
    scan_data = {
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

    # 1. Generate HTML via AI
    print("DEBUG: Calling generate_html_report...", flush=True)
    raw_html = generate_html_report(scan_data)
    print(f"DEBUG: generate_html_report returned {len(raw_html)} chars.", flush=True)
    
    # 2. Sanitize HTML for safety including inline CSS
    print(f"DEBUG: Starting HTML sanitization (Bleach)...", flush=True)
    from bleach.css_sanitizer import CSSSanitizer
    css_sanitizer = CSSSanitizer()
    
    print("DEBUG: Executing bleach.clean...", flush=True)
    clean_html = bleach.clean(
        raw_html, 
        tags=ALLOWED_TAGS, 
        attributes=ALLOWED_ATTRS,
        css_sanitizer=css_sanitizer,
        strip=True
    )
    print(f"DEBUG: HTML sanitization complete. Cleaned HTML length: {len(clean_html)} chars.", flush=True)
    
    # Re-inject the style content if bleach stripped it too aggressively 
    # (Bleach usually strips <style> tags content unless handled)
    # For WeasyPrint, inline styles are best, but AI prompt should already handle this.

    # 3. Render to PDF
    try:
        # Resolve media root as a string
        base_dir = str(settings.BASE_DIR)
        media_root = str(getattr(settings, 'MEDIA_ROOT', os.path.join(base_dir, 'media')))
        reports_dir = os.path.join(media_root, 'reports')
        
        # Ensure reports directory exists before passing to renderer
        os.makedirs(reports_dir, exist_ok=True)
        
        filename = f"ARMORA_Report_{scan.id}_{scan.timestamp.strftime('%Y%H%M%S')}.pdf"
        output_path = os.path.join(reports_dir, filename)
        
        print(f"DEBUG: Calling render_pdf for {output_path}...", flush=True)
        success = render_pdf(clean_html, output_path)
        print(f"DEBUG: render_pdf finished. Success: {success}", flush=True)
        
        if success:
            return output_path, None
        else:
            return None, "PDF rendering failed."
    except Exception as e:
        return None, f"Report service error: {str(e)}"
