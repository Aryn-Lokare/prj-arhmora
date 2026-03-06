import hashlib
import time
import logging
import httpx
import asyncio

logger = logging.getLogger(__name__)

# Default timeout for all scanner HTTP requests (seconds).
REQUEST_TIMEOUT = 10
MAX_WORKERS = 10

class HttpClient:
    """
    Asynchronous HTTP client for the Armora scanner.
    """

    def __init__(self, timeout: int = REQUEST_TIMEOUT, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.semaphore = asyncio.Semaphore(MAX_WORKERS)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=verify_ssl,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20)
        )

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
        headers: dict = None,
        trace_id: str = None
    ) -> dict:
        """
        Send an async HTTP request and return a normalised result dict.
        """
        _headers = {"User-Agent": "Armora-Scanner/3.0"}
        if trace_id:
            _headers["X-Armora-Trace-ID"] = trace_id
        if headers:
            _headers.update(headers)

        async with self.semaphore:
            try:
                start = time.time()
                resp = await self.client.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    headers=_headers
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

            except httpx.TimeoutException:
                logger.warning(f"Request timed out: {url}")
                return self._empty_response(url, timed_out=True)
            except Exception as exc:
                logger.error(f"Async HTTP request failed for {url}: {exc}")
                return self._empty_response(url)

    async def get(self, url: str, params: dict = None, headers: dict = None) -> dict:
        return await self.send_request(url, method="GET", params=params, headers=headers)

    async def post(self, url: str, data: dict = None, headers: dict = None) -> dict:
        return await self.send_request(url, method="POST", data=data, headers=headers)

    @staticmethod
    def _empty_response(url: str, timed_out: bool = False) -> dict:
        return {
            "status_code": 0,
            "body": "",
            "body_hash": "",
            "response_time": float(REQUEST_TIMEOUT) if timed_out else 0.0,
            "headers": {},
        }

    async def close(self):
        await self.client.aclose()
