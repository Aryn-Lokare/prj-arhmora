import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.models import ScanHistory

scan = ScanHistory.objects.get(id=201)
findings = scan.findings.filter(classification__in=['confirmed', 'likely'])

print(f"Checking {findings.count()} findings...")
total_len = 0
for f in findings:
    expl_len = len(f.explanation_technical or "")
    rem_len = len(f.remediation_technical or "")
    total_len += expl_len + rem_len
    print(f"Finding {f.id}: Expl={expl_len}, Rem={rem_len}")

print(f"Total content length: {total_len} chars")
