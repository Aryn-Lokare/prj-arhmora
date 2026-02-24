"""
Armora v2 — Attack Payloads Module.
Curated payloads for active exploit verification across 5 vulnerability classes.
"""

from .sqli_payloads import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES, SQLI_TIME_PAYLOADS
from .xss_payloads import XSS_PAYLOADS, XSS_CONFIRMATION_SIGNATURES
from .ssrf_payloads import SSRF_PAYLOADS, SSRF_SUCCESS_SIGNATURES
from .lfi_payloads import LFI_PAYLOADS, LFI_SUCCESS_SIGNATURES
from .rce_payloads import RCE_PAYLOADS, RCE_SUCCESS_SIGNATURES, RCE_TIME_PAYLOADS

__all__ = [
    'SQLI_PAYLOADS', 'SQLI_ERROR_SIGNATURES', 'SQLI_TIME_PAYLOADS',
    'XSS_PAYLOADS', 'XSS_CONFIRMATION_SIGNATURES',
    'SSRF_PAYLOADS', 'SSRF_SUCCESS_SIGNATURES',
    'LFI_PAYLOADS', 'LFI_SUCCESS_SIGNATURES',
    'RCE_PAYLOADS', 'RCE_SUCCESS_SIGNATURES', 'RCE_TIME_PAYLOADS',
]
