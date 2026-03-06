import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from ..payloads.ssrf_payloads import SSRF_PAYLOADS, SSRF_SUCCESS_SIGNATURES
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence
from ..intelligence.oob_manager import oob

logger = logging.getLogger(__name__)

# ... URL_PARAM_HINTS ... legacy ...

_MAX_WORKERS = 20

class SSRFDetector:
    """SSRF detector with OOB support."""

    vuln_type = "Server-Side Request Forgery (SSRF)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict, extra_payloads: list = None) -> list:
        # ... logic ...
        findings = []

        # Target IP check
        internal_result = self._check_internal_ip(url)
        if internal_result:
            findings.append(internal_result)

        for param, original_value in params.items():
            if not self._is_url_param(param, original_value):
                continue
            result = self._test_parameter(url, params, param, extra_payloads)
            if result:
                findings.append(result)

        return findings

    def _is_url_param(self, name: str, value: str) -> bool:
        # Same as before
        URL_PARAM_HINTS = {
            "url", "uri", "link", "href", "src", "source", "dest", "destination",
            "redirect", "redirect_url", "return", "return_url", "next", "goto",
            "target", "out", "continue", "view", "page", "feed", "host",
            "site", "callback", "path", "file", "reference", "ref",
        }
        if name.lower() in URL_PARAM_HINTS:
            return True
        if str(value).startswith(("http://", "https://", "/", "ftp://")):
            return True
        return False

    def _check_internal_ip(self, url: str):
        # Same as before
        try:
            hostname = urlparse(url).hostname
            if not hostname: return None
            ip = socket.gethostbyname(hostname)
            if self._is_private_ip(ip):
                confidence = calculate_confidence(True, True, False)
                return {
                    "type": self.vuln_type,
                    "parameter": "__target_url__",
                    "confidence": confidence,
                    "status": classify_confidence(confidence),
                    "evidence": {
                        "payload": url,
                        "internal_ip": ip,
                        "signatures_matched": [f"Resolves to private IP: {ip}"],
                    },
                }
        except: pass
        return None

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        # Same as before
        parts = ip.split('.')
        if len(parts) != 4: return False
        try: first, second = int(parts[0]), int(parts[1])
        except: return False
        return (first == 127 or first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168) or first == 0)

    def _test_parameter(self, url: str, all_params: dict, param: str, extra_payloads: list = None):
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None

        result_holder = []
        
        # 1. OOB Token Generation
        oob_token = oob.generate_token()
        oob_payload = oob.get_http_payload(oob_token)
        
        # 2. Add OOB payload and mutation tips to the test list
        payloads_to_test = list(SSRF_PAYLOADS) + [oob_payload]
        if extra_payloads:
            payloads_to_test.extend(extra_payloads)

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, p, baseline
                ): p
                for p in payloads_to_test
            }
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        result_holder.append(res)
                        break
                except Exception as exc:
                    logger.warning(f"SSRF payload future error: {exc}")

        # 3. Final Blind Check (OOB Polling)
        if not result_holder:
            # Wait 2 seconds for DNS/HTTP propagation
            time.sleep(2)
            if oob.check_interactions(oob_token):
                confidence = calculate_confidence(True, True, False) # 100% confidence
                return {
                    "type": self.vuln_type,
                    "parameter": param,
                    "confidence": confidence,
                    "status": "Confirmed",
                    "evidence": {
                        "payload": oob_payload,
                        "detail": "Out-of-band interaction (callback) detected.",
                        "signatures_matched": ["OOB Callback Received"],
                    },
                }

        return result_holder[0] if result_holder else None

    def _test_single_payload(self, url: str, all_params: dict, param: str, payload: str, baseline: dict):
        test_params = dict(all_params)
        test_params[param] = payload

        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        sigs = self.analyzer.find_signatures(test_resp["body"], SSRF_SUCCESS_SIGNATURES)
        server_err = self.analyzer.is_server_error(test_resp["status_code"])

        confidence = calculate_confidence(bool(sigs), bool(sigs), server_err)
        status = classify_confidence(confidence)

        if status != "Discard":
            return {
                "type": self.vuln_type,
                "parameter": param,
                "confidence": confidence,
                "status": status,
                "evidence": {
                    "payload": payload,
                    "signatures_matched": sigs,
                    "status_code": test_resp["status_code"],
                },
            }
        return None
