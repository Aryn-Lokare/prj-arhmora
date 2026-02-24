"""
SQL Injection Detector — Armora v2.

Exploit-verification-first:
1. Send a baseline request.
2. Inject payloads into each parameter — concurrently.
3. Compare responses for SQL error signatures & timing anomalies.
4. Score with the simple confidence model.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..payloads.sqli_payloads import (
    SQLI_PAYLOADS,
    SQLI_TIME_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
)
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence
from ..intelligence.exploit_verifier import classify_exploit

logger = logging.getLogger(__name__)

# Max parallel payload requests per parameter
_MAX_WORKERS = 20


class SQLiDetector:
    """Independent SQL Injection detector — no ML, no Gemini."""

    vuln_type = "SQL Injection"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    def detect(self, url: str, params: dict) -> list:
        """
        Test every parameter in *params* for SQL injection.

        Args:
            url: Base URL (without query string).
            params: ``{"param_name": "original_value", ...}``

        Returns:
            List of structured finding dicts (only Confirmed / Likely).
        """
        findings = []

        for param, original_value in params.items():
            result = self._test_parameter(url, params, param, original_value)
            if result:
                findings.append(result)

        return findings

    # ------------------------------------------------------------------ #
    #  Internals                                                         #
    # ------------------------------------------------------------------ #

    def _test_parameter(self, url: str, all_params: dict, param: str, original_value: str):
        """Inject all payloads concurrently into a parameter and evaluate."""

        # 1. Baseline request (shared, done once before concurrent tests)
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None  # Target unreachable

        # 2. Fire error-based + time-based payloads concurrently
        error_payloads = SQLI_PAYLOADS
        time_payloads = SQLI_TIME_PAYLOADS

        if hasattr(self, "intelligence") and self.intelligence:
            error_payloads = self.intelligence.optimize_payloads(self.vuln_type, error_payloads)
            # Time payloads are usually fewer and standard, but we could optimize them too
            # time_payloads = self.intelligence.optimize_payloads(f"{self.vuln_type} (Time)", time_payloads)

        all_payloads = [(p, False) for p in error_payloads] + \
                       [(p, True)  for p in time_payloads]

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
                        # Cancel remaining futures once we have a finding
                        for f in futures:
                            f.cancel()
                        break
                except Exception as exc:
                    logger.warning(f"SQLi payload future error: {exc}")

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
        """Test one payload inside the shared session thread."""
        test_params = dict(all_params)
        test_params[param] = payload

        # REUSE self.http (which uses the shared session)
        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        diff = self.analyzer.compare(baseline, test_resp)

        if is_time_based:
            if diff["time_based_suspected"]:
                # Use multi-signal classifier
                verification = classify_exploit(payload, test_resp, True)
                
                if verification["type"] == "SQL Injection":
                    return self._build_result(
                        param=param,
                        payload=payload,
                        confidence=verification["confidence"],
                        status="Confirmed",
                        sigs=verification["evidence"],
                        diff=diff,
                        test_resp=test_resp,
                    )
                elif "Suspicious" in verification["type"]:
                    # Still report as suspicious but with lower confidence
                    return self._build_result(
                        param=param,
                        payload=payload,
                        confidence=verification["confidence"],
                        status="Likely",
                        sigs=verification["evidence"],
                        diff=diff,
                        test_resp=test_resp,
                        v_type=verification["type"]
                    )
        else:
            sigs = self.analyzer.find_signatures(test_resp["body"], SQLI_ERROR_SIGNATURES)
            
            # Use multi-signal classifier for error-based too
            test_resp["signatures_found"] = sigs
            verification = classify_exploit(payload, test_resp, False)
            
            if verification["type"] == "SQL Injection":
                return self._build_result(
                    param=param,
                    payload=payload,
                    confidence=verification["confidence"],
                    status="Confirmed",
                    sigs=verification["evidence"],
                    diff=diff,
                    test_resp=test_resp,
                )

        return None

    def _build_result(self, *, param, payload, confidence, status, sigs, diff, test_resp, v_type=None) -> dict:
        return {
            "type": v_type or self.vuln_type,
            "parameter": param,
            "confidence": confidence,
            "status": status,
            "evidence": {
                "payload": payload,
                "signatures_matched": sigs,
                "status_code": test_resp["status_code"],
                "response_time_delta": diff["response_time_delta"],
                "body_hash_changed": diff["body_hash_changed"],
            },
        }
