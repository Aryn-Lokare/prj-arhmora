"""
Response Analyzer — Armora v2.

Compares a baseline response against a test (payload-injected) response
to detect exploitable behaviour differences.
"""

import logging

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """
    Stateless comparison engine.

    Takes two standardised response dicts (from ``HttpClient``) and
    returns a structured diff result.
    """

    # Time-delta threshold (seconds) that suggests a time-based injection.
    TIME_DELTA_THRESHOLD = 4.0

    def compare(self, baseline: dict, test: dict) -> dict:
        """
        Compare *baseline* and *test* responses.

        Returns:
            {
                "body_hash_changed": bool,
                "status_code_changed": bool,
                "status_code_baseline": int,
                "status_code_test": int,
                "response_time_delta": float,
                "time_based_suspected": bool,
                "error_signatures_found": list[str],
            }
        """
        body_hash_changed = baseline.get("body_hash") != test.get("body_hash")

        status_baseline = baseline.get("status_code", 0)
        status_test = test.get("status_code", 0)
        status_changed = status_baseline != status_test

        time_delta = (test.get("response_time", 0) - baseline.get("response_time", 0))
        time_suspected = time_delta >= self.TIME_DELTA_THRESHOLD

        return {
            "body_hash_changed": body_hash_changed,
            "status_code_changed": status_changed,
            "status_code_baseline": status_baseline,
            "status_code_test": status_test,
            "response_time_delta": round(time_delta, 4),
            "time_based_suspected": time_suspected,
            "error_signatures_found": [],  # Populated by detectors themselves
        }

    @staticmethod
    def find_signatures(body: str, signatures: list) -> list:
        """
        Return every signature from *signatures* found in *body*
        (case-insensitive).
        """
        if not body:
            return []
        body_lower = body.lower()
        return [sig for sig in signatures if sig.lower() in body_lower]

    @staticmethod
    def is_server_error(status_code: int) -> bool:
        """True when the HTTP status indicates a server-side error."""
        return 500 <= status_code < 600
