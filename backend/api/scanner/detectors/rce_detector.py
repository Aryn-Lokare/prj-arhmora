"""
RCE (Remote Code Execution) Detector — Armora v2.

Exploit-verification-first:
1. Baseline request.
2. Inject OS command payloads into parameters — concurrently.
3. Check for canary output and time-based delays.
4. Score with the simple confidence model.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..payloads.rce_payloads import (
    RCE_PAYLOADS,
    RCE_TIME_PAYLOADS,
    RCE_SUCCESS_SIGNATURES,
)
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence
from ..intelligence.exploit_verifier import classify_exploit

logger = logging.getLogger(__name__)

_MAX_WORKERS = 20


class RCEDetector:
    """Independent RCE detector — no ML, no Gemini."""

    vuln_type = "Remote Code Execution (RCE)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict) -> list:
        """
        Test every parameter for OS command injection.

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

        # 2. Fire output-based + time-based payloads concurrently
        all_payloads = [(p, False) for p in RCE_PAYLOADS] + \
                       [(p, True)  for p in RCE_TIME_PAYLOADS]

        result_holder = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, payload, baseline, is_time
                ): payload
                for payload, is_time in all_payloads
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
                    logger.warning(f"RCE payload future error: {exc}")

        return result_holder[0] if result_holder else None

    def _test_single_payload(
        self,
        url: str,
        all_params: dict,
        param: str,
        payload: str,
        baseline: dict,
        is_time_based: bool,
    ):
        """Test one payload inside shared session."""
        test_params = dict(all_params)
        test_params[param] = payload

        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        diff = self.analyzer.compare(baseline, test_resp)

        if is_time_based:
            if diff["time_based_suspected"]:
                # Use multi-signal classifier
                verification = classify_exploit(payload, test_resp, True)
                
                if verification["type"] == "Remote Code Execution":
                    return {
                        "type": self.vuln_type,
                        "parameter": param,
                        "confidence": verification["confidence"],
                        "status": "Confirmed",
                        "evidence": {
                            "payload": payload,
                            "signatures_matched": verification["evidence"],
                            "response_time_delta": diff["response_time_delta"],
                        },
                    }
                elif "Suspicious" in verification["type"]:
                    return {
                        "type": verification["type"],
                        "parameter": param,
                        "confidence": verification["confidence"],
                        "status": "Likely",
                        "evidence": {
                            "payload": payload,
                            "signatures_matched": verification["evidence"],
                            "response_time_delta": diff["response_time_delta"],
                        },
                    }
        else:
            sigs = self.analyzer.find_signatures(test_resp["body"], RCE_SUCCESS_SIGNATURES)
            
            # Use multi-signal classifier for output-based too
            verification = classify_exploit(payload, test_resp, False)
            
            if verification["type"] == "Remote Code Execution":
                return {
                    "type": self.vuln_type,
                    "parameter": param,
                    "confidence": verification["confidence"],
                    "status": "Confirmed",
                    "evidence": {
                        "payload": payload,
                        "signatures_matched": verification["evidence"],
                        "status_code": test_resp["status_code"],
                        "body_hash_changed": diff["body_hash_changed"],
                    },
                }

        return None
