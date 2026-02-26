"""
HTTP Client — Armora v2.

Lightweight HTTP client for sending baseline and payload requests.
Uses httpx for async support with a synchronous fallback via requests.
"""

import hashlib
import time
import logging
import requests as sync_requests

logger = logging.getLogger(__name__)

# Default timeout for all scanner HTTP requests (seconds).
REQUEST_TIMEOUT = 10


class HttpClient:
    """
    Synchronous HTTP client for the Armora scanner.

    Each call returns a standardised response dict:
        {
            "status_code": int,
            "body": str,
            "body_hash": str,          # SHA-256 of the response body
            "response_time": float,    # Seconds
            "headers": dict,
        }
    """

    def __init__(self, timeout: int = REQUEST_TIMEOUT, verify_ssl: bool = False, session=None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._owns_session = session is None
        self.session = session or sync_requests.Session()
        
        # Only configure adapters/SSL on sessions we own (not shared ones)
        if self._owns_session:
            adapter = sync_requests.adapters.HTTPAdapter(
                pool_connections=50,
                pool_maxsize=50,
                max_retries=1
            )
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.verify = verify_ssl

        # Suppress InsecureRequestWarning when verify_ssl is False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    def send_request(
        self,
        url: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
        headers: dict = None,
    ) -> dict:
        """
        Send an HTTP request and return a normalised result dict.

        Args:
            url: Target URL.
            method: HTTP method (GET, POST, etc.).
            params: Query-string parameters (GET params).
            data: Form body (POST params).
            headers: Additional headers.

        Returns:
            Standardised response dict.  On failure the dict still has
            all keys but with safe defaults so callers never need to
            guard against missing keys.
        """
        _headers = {"User-Agent": "Armora-Scanner/2.0"}
        if headers:
            _headers.update(headers)

        try:
            start = time.time()
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=_headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
            elapsed = time.time() - start

            body = resp.text
            return {
                "status_code": resp.status_code,
                "body": body,
                "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
                "response_time": round(elapsed, 4),
                "headers": dict(resp.headers),
            }

        except sync_requests.exceptions.Timeout:
            logger.warning(f"Request timed out: {url}")
            return self._empty_response(url, timed_out=True)

        except Exception as exc:
            logger.error(f"HTTP request failed for {url}: {exc}")
            return self._empty_response(url)

    def get(self, url: str, params: dict = None, headers: dict = None) -> dict:
        """Convenience wrapper for GET requests."""
        return self.send_request(url, method="GET", params=params, headers=headers)

    def post(self, url: str, data: dict = None, headers: dict = None) -> dict:
        """Convenience wrapper for POST requests."""
        return self.send_request(url, method="POST", data=data, headers=headers)

    # ------------------------------------------------------------------ #
    #  Internals                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_response(url: str, timed_out: bool = False) -> dict:
        """Return a safe empty-response dict so callers never crash."""
        return {
            "status_code": 0,
            "body": "",
            "body_hash": "",
            "response_time": REQUEST_TIMEOUT if timed_out else 0.0,
            "headers": {},
        }
