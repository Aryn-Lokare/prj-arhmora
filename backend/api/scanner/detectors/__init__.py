"""Armora v2 — Detector Modules."""

from .sqli_detector import SQLiDetector
from .xss_detector import XSSDetector
from .ssrf_detector import SSRFDetector
from .lfi_detector import LFIDetector
from .rce_detector import RCEDetector

ALL_DETECTORS = [SQLiDetector, XSSDetector, SSRFDetector, LFIDetector, RCEDetector]

__all__ = [
    'SQLiDetector', 'XSSDetector', 'SSRFDetector',
    'LFIDetector', 'RCEDetector', 'ALL_DETECTORS',
]
