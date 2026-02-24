import os
import django
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.scanner.report_service import generate_pdf_report

scan_id = 201
print(f"DEBUG: Starting PDF generation test for scan {scan_id}...")
try:
    path, error = generate_pdf_report(scan_id)
    if error:
        print(f"DEBUG: FAILED with error: {error}")
    else:
        print(f"DEBUG: SUCCESS! PDF created at: {path}")
except Exception as e:
    print(f"DEBUG: CRITICAL EXCEPTION: {str(e)}")
