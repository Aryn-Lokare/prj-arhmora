"""
LFI (Local File Inclusion) Detector — Armora v2.

Exploit-verification-first:
1. Baseline request.
2. Inject path-traversal payloads into file/path parameters — concurrently.
3. Check for known system-file content in the response.
4. Score with the simple confidence model.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..payloads.lfi_payloads import LFI_PAYLOADS, LFI_SUCCESS_SIGNATURES
from ..utils.http_client import HttpClient
from ..utils.response_analyzer import ResponseAnalyzer
from ..utils.confidence import calculate_confidence, classify_confidence

logger = logging.getLogger(__name__)

# Parameters whose names suggest they accept file paths.
FILE_PARAM_HINTS = {
    "file", "path", "page", "template", "include", "inc", "dir", "document",
    "folder", "root", "pg", "style", "pdf", "img", "doc", "filename",
    "filepath", "loc", "location", "read", "retrieve", "load",
    "view", "content", "layout", "mod", "conf",
}

_MAX_WORKERS = 20


class LFIDetector:
    """Independent LFI detector — no ML, no Gemini."""

    vuln_type = "Local File Inclusion (LFI)"

    def __init__(self, session=None):
        self.http = HttpClient(session=session)
        self.analyzer = ResponseAnalyzer()

    def detect(self, url: str, params: dict) -> list:
        """
        Test file/path parameters for LFI.

        Returns:
            List of structured finding dicts (only Confirmed / Likely).
        """
        findings = []
        for param, original_value in params.items():
            if not self._is_file_param(param, original_value):
                continue
            result = self._test_parameter(url, params, param)
            if result:
                findings.append(result)
        return findings

    def _is_file_param(self, name: str, value: str) -> bool:
        """Heuristic: does this param likely accept a file path?"""
        if name.lower() in FILE_PARAM_HINTS:
            return True
        if "/" in value or "\\" in value or value.endswith((".php", ".html", ".txt", ".log", ".conf")):
            return True
        return False

    def _test_parameter(self, url: str, all_params: dict, param: str):
        # 1. Baseline
        baseline = self.http.get(url, params=all_params)
        if baseline["status_code"] == 0:
            return None

        # 2. Fire all LFI payloads concurrently
        result_holder = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_single_payload, url, all_params, param, payload, baseline
                ): payload
                for payload in LFI_PAYLOADS
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
                    logger.warning(f"LFI payload future error: {exc}")

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
        sigs = self.analyzer.find_signatures(test_resp["body"], LFI_SUCCESS_SIGNATURES)
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
                    "body_hash_changed": diff["body_hash_changed"],
                },
            }

        return None
