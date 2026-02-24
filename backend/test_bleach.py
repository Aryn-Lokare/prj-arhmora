import bleach
from bleach.css_sanitizer import CSSSanitizer
import sys

html = "<html><body><h1 style='color: red;'>Test</h1></body></html>"
ALLOWED_TAGS = ['html', 'body', 'h1', 'style']
ALLOWED_ATTRS = {'*': ['style']}

print("DEBUG: Initializing CSSSanitizer...", flush=True)
try:
    css_sanitizer = CSSSanitizer()
    print("DEBUG: Executing bleach.clean...", flush=True)
    clean = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        css_sanitizer=css_sanitizer
    )
    print("DEBUG: Success!", flush=True)
    print(f"Cleaned: {clean}")
except Exception as e:
    print(f"DEBUG: Exception: {str(e)}", flush=True)
    import traceback
    traceback.print_exc()
