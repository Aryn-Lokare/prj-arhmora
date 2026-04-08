import hashlib
import time
import logging
import requests
import urllib3

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default timeout for all scanner HTTP requests (seconds).
REQUEST_TIMEOUT = 10

class HttpClient:
    """
    Synchronous HTTP client for the Armora scanner.
    Uses requests.Session for connection pooling across threads.
    """

    def __init__(self, timeout: int = REQUEST_TIMEOUT, verify_ssl: bool = False, session=None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Share a session across threads for connection pooling
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "Armora-Scanner/3.0"})
            self.session.verify = verify_ssl

    def send_request(
        self,
        url: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
        headers: dict = None,
    ) -> dict:
        """
        Send a synchronous HTTP request and return a normalised result dict.
        """
        try:
            start = time.time()
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
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

        except requests.exceptions.Timeout:
            logger.warning(f"Request timed out: {url}")
            return self._empty_response(url, timed_out=True)
        except Exception as exc:
            logger.error(f"HTTP request failed for {url}: {exc}")
            return self._empty_response(url)

    def get(self, url: str, params: dict = None, headers: dict = None) -> dict:
        return self.send_request(url, method="GET", params=params, headers=headers)

    def post(self, url: str, data: dict = None, headers: dict = None) -> dict:
        return self.send_request(url, method="POST", data=data, headers=headers)

    @staticmethod
    def _empty_response(url: str, timed_out: bool = False) -> dict:
        return {
            "status_code": 0,
            "body": "",
            "body_hash": "",
            "response_time": float(REQUEST_TIMEOUT) if timed_out else 0.0,
            "headers": {},
        }

