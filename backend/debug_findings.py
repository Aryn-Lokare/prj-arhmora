import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.models import ScanHistory, ScanFinding

try:
    scan = ScanHistory.objects.get(id=201)
    findings = scan.findings.all()
    print(f"Total findings for scan 201: {findings.count()}")
    for f in findings:
        print(f"Finding: {f.v_type}, Severity: {f.severity}, Classification: {f.classification}")
    
    sig_findings = findings.filter(classification__in=['confirmed', 'likely'])
    print(f"Significant findings (confirmed/likely): {sig_findings.count()}")
except Exception as e:
    print(f"Error: {e}")
