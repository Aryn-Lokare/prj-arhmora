"""
SSRF Detector — Armora v2.

Exploit-verification-first:
1. Baseline request.
2. Inject SSRF payloads (internal IPs, cloud metadata) — concurrently.
3. Check for internal/cloud content in the response.
4. Score with the simple confidence model.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from ..payloads.ssrf_payloads import SSRF_PAYLOADS, SSRF_SUCCESS_SIGNATURES
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence

logger = logging.getLogger(__name__)

# Parameters whose names suggest they accept URLs.
URL_PARAM_HINTS = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "return", "return_url", "next", "goto",
    "target", "out", "continue", "view", "page", "feed", "host",
    "site", "callback", "path", "file", "reference", "ref",
}

_MAX_WORKERS = 20


class SSRFDetector:
    """Independent SSRF detector — no ML, no Gemini."""

    vuln_type = "Server-Side Request Forgery (SSRF)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict) -> list:
        """
        Test URL-like parameters for SSRF.

        Returns:
            List of structured finding dicts (only Confirmed / Likely).
        """
        findings = []

        # Also check if the target URL itself resolves to an internal IP.
        internal_result = self._check_internal_ip(url)
        if internal_result:
            findings.append(internal_result)

        for param, original_value in params.items():
            # Only test parameters that look like they accept URLs/paths.
            if not self._is_url_param(param, original_value):
                continue
            result = self._test_parameter(url, params, param)
            if result:
                findings.append(result)

        return findings

    def _is_url_param(self, name: str, value: str) -> bool:
        """Heuristic: does this param likely accept a URL?"""
        if name.lower() in URL_PARAM_HINTS:
            return True
        if value.startswith(("http://", "https://", "/", "ftp://")):
            return True
        return False

    def _check_internal_ip(self, url: str):
        """Check if the target URL itself resolves to a private IP."""
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return None
            ip = socket.gethostbyname(hostname)
            if self._is_private_ip(ip):
                confidence = calculate_confidence(
                    exploit_success=True,
                    strong_signature=True,
                    server_error=False,
                )
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
        except Exception:
            pass
        return None

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in a private/reserved range (RFC 1918 + loopback)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        if first == 127:  # Loopback
            return True
        if first == 10:  # 10.0.0.0/8
            return True
        if first == 172 and 16 <= second <= 31:  # 172.16.0.0/12
            return True
        if first == 192 and second == 168:  # 192.168.0.0/16
            return True
        if first == 0:  # 0.0.0.0/8
            return True
        return False

    def _test_parameter(self, url: str, all_params: dict, param: str):
        # 1. Baseline
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None

        # 2. Fire all SSRF payloads concurrently
        result_holder = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, payload, baseline
                ): payload
                for payload in SSRF_PAYLOADS
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
                    logger.warning(f"SSRF payload future error: {exc}")

        return result_holder[0] if result_holder else None

    def _test_single_payload(
        self,
        url: str,
        all_params: dict,
        param: str,
        payload: str,
        baseline: dict,
    ):
        """Test one payload. Maintains connection pool."""
        test_params = dict(all_params)
        test_params[param] = payload

        test_resp = self.http.get(url, params=test_params)
        if test_resp["status_code"] == 0:
            return None

        sigs = self.analyzer.find_signatures(test_resp["body"], SSRF_SUCCESS_SIGNATURES)
        server_err = self.analyzer.is_server_error(test_resp["status_code"])

        exploit_success = bool(sigs)
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
                    "signatures_matched": sigs,
                    "status_code": test_resp["status_code"],
                },
            }

        return None
