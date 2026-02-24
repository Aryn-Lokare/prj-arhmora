import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.models import ScanHistory
from api.scanner.ai_content_generator import generate_structured_intelligence

# Test with scan 202
try:
    scan = ScanHistory.objects.get(id=202)
    findings = scan.findings.filter(classification='confirmed')
    
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
    
    print("Calling generate_structured_intelligence...")
    ai_data = generate_structured_intelligence(scan_metadata)
    
    print("\n--- AI JSON DATA ---")
    print(json.dumps(ai_data, indent=2))
    
    # Check for business_impact in vulnerabilities
    for i, v in enumerate(ai_data.get('vulnerabilities', [])):
        print(f"\nVulnerability {i+1}: {v.get('title')}")
        impact = v.get('business_impact')
        if impact:
            print(f"Business Impact Present: {len(impact)} chars")
        else:
            print("Business Impact MISSING!")

except Exception as e:
    print(f"Error: {e}")
