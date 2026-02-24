import os
import django
import traceback

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.scanner.pdf_renderer import render_pdf

html = "<html><body><h1>Django Context Test</h1><p>Testing with settings loaded.</p></body></html>"
output = "test_django.pdf"
log_file = "test_debug.log"

with open(log_file, "w") as log:
    try:
        log.write(f"Starting PDF render test to {output}...\n")
        # Ensure media dir exists
        from django.conf import settings
        os.makedirs(os.path.join(settings.BASE_DIR, 'media', 'reports'), exist_ok=True)
        
        success = render_pdf(html, output)
        if success:
            log.write(f"SUCCESS: PDF rendered to {os.path.abspath(output)}\n")
        else:
            log.write("FAILED: Minor failure in render_pdf.\n")
    except Exception:
        log.write("CRITICAL FAILURE in test script:\n")
        traceback.print_exc(file=log)

print(f"Test finished. Check {log_file} for details.")
