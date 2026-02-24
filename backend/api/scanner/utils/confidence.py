"""
Confidence Scoring — Armora v2.

Simple, transparent confidence model.  No ML, no multi-factor engine.

Scoring rules (exact spec):
    +70  exploit verified
    +20  strong attack signature found
    +10  server error detected (5xx)

Classification:
    >=80  →  Confirmed
    50-79 →  Likely
    <50   →  Discard  (not returned to caller)
"""

import logging

logger = logging.getLogger(__name__)


def calculate_confidence(
    exploit_success: bool = False,
    strong_signature: bool = False,
    server_error: bool = False,
) -> int:
    """
    Calculate a transparent confidence score.

    Returns:
        Integer confidence score (0–100).
    """
    confidence = 0

    if exploit_success:
        confidence += 70

    if strong_signature:
        confidence += 20

    if server_error:
        confidence += 10

    return min(confidence, 100)


def classify_confidence(confidence: int) -> str:
    """
    Map a confidence score to a human-readable status.

    Returns:
        ``"Confirmed"`` | ``"Likely"`` | ``"Discard"``
    """
    if confidence >= 80:
        return "Confirmed"
    elif confidence >= 50:
        return "Likely"
    else:
        return "Discard"
