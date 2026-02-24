"""
XSS Detector — Armora v2.

Exploit-verification-first:
1. Baseline request.
2. Inject XSS payloads into each parameter — concurrently.
3. Check if payload / canary is reflected in the response body.
4. Score with the simple confidence model.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..payloads.xss_payloads import XSS_PAYLOADS, XSS_CONFIRMATION_SIGNATURES, XSS_CANARY
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence

logger = logging.getLogger(__name__)

_MAX_WORKERS = 20


class XSSDetector:
    """Independent Reflected XSS detector — no ML, no Gemini."""

    vuln_type = "Cross-Site Scripting (XSS)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict) -> list:
        """
        Test every parameter in *params* for reflected XSS.

        Returns:
            List of structured finding dicts (only Confirmed / Likely).
        """
        findings = []
        for param, original_value in params.items():
            result = self._test_parameter(url, params, param)
            if result:
                findings.append(result)
        return findings

    def _test_parameter(self, url: str, all_params: dict, param: str):
        # 1. Baseline
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None

        # 2. Fire all XSS payloads concurrently
        result_holder = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, payload, baseline
                ): payload
                for payload in XSS_PAYLOADS
            }
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        result_holder.append(res)
                        for f in futures:
                            f.cancel()
                        break
                except Exception as exc:
                    logger.warning(f"XSS payload future error: {exc}")

        return result_holder[0] if result_holder else None

    def _test_single_payload(
        self,
        url: str,
        all_params: dict,
        param: str,
        payload: str,
        baseline: dict,
    ):
        """Test one payload. Reuses shared session."""
        test_params = dict(all_params)
        test_params[param] = payload

        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        diff = self.analyzer.compare(baseline, test_resp)
        sigs = self.analyzer.find_signatures(test_resp["body"], XSS_CONFIRMATION_SIGNATURES)
        server_err = self.analyzer.is_server_error(test_resp["status_code"])

        # Exploit success = payload fully reflected in response
        exploit_success = (payload.lower() in test_resp["body"].lower()) or bool(sigs)

        # Strong signature = canary or event handler reflected
        strong_sig = bool(sigs)

        confidence = calculate_confidence(
            exploit_success=exploit_success,
            strong_signature=strong_sig,
            server_error=server_err,
        )
        status = classify_confidence(confidence)

        if status != "Discard":
            return {
                "type": self.vuln_type,
                "parameter": param,
                "confidence": confidence,
                "status": status,
                "evidence": {
                    "payload": payload,
                    "reflected": True,
                    "signatures_matched": sigs,
                    "status_code": test_resp["status_code"],
                    "body_hash_changed": diff["body_hash_changed"],
                },
            }

        return None
