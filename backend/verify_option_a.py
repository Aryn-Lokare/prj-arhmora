import os
from api.scanner.pdf_renderer import render_report_to_pdf

sample_data = {
    "target_url": "http://example-target.com",
    "timestamp": "2026-02-22 16:00:00",
    "executive_summary": "This is a sample executive summary for the deterministic ReportLab report.",
    "overall_risk_analysis": "The overall security posture is simulated as moderate.",
    "vulnerabilities": [
        {
            "title": "Sample SQL Injection",
            "technical_explanation": "A simulated SQL injection vulnerability found in the login form.",
            "risk_analysis": "High risk of data exfiltration.",
            "business_impact": "Financial loss due to data breach and regulatory fines.",
            "remediation": "Use parameterized queries and sanitize user input."
        }
    ]
}

output = "test_option_a.pdf"
print(f"Generating deterministic PDF to {output}...")
success = render_report_to_pdf(sample_data, output)

if success:
    print(f"SUCCESS: {os.path.abspath(output)}")
else:
    print("FAILED to generate PDF.")
