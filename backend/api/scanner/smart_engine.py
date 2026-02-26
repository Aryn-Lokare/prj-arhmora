"""
Smart Detection Engine — Armora v2 (Layer 1).

Core detection pipeline that:
1. Pre-filters URLs (skips static resources / CDN).
2. Extracts injectable parameters from GET and POST vectors.
3. Runs all 5 detectors against each parameter set — concurrently per URL.
4. Aggregates findings and discards low-confidence results.
5. Returns only Confirmed + Likely findings.

No ML. No anomaly scoring. No probability-based logic.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .utils.prefilter import PreFilter
from .utils.http_client import HttpClient
from .detectors import SQLiDetector, XSSDetector, SSRFDetector, LFIDetector, RCEDetector

logger = logging.getLogger(__name__)

# Number of URLs to scan in parallel
_URL_WORKERS = 20


class SmartDetectionEngine:
    """
    Lightweight exploit-verification engine.

    Runs all registered detectors against every injectable parameter
    discovered in the target and crawled URLs — concurrently per URL.
    """

    def __init__(self):
        self.prefilter = PreFilter()
        self.detector_classes = [
            SQLiDetector,
            XSSDetector,
            SSRFDetector,
            LFIDetector,
            RCEDetector,
        ]
        # Sharing one session across all URLs and detectors enables massive connection pooling
        self._shared_client = HttpClient()
        self._shared_session = self._shared_client.session


    def scan(self, urls: list, forms: list = None, intelligence=None) -> list:
        """
        Run the full detection pipeline across *urls* concurrently.

        Args:
            urls: List of crawled URLs (may include query strings).
            forms: Optional list of discovered forms (Crawler output).

        Returns:
            List of structured finding dicts.
            Only ``Confirmed`` and ``Likely`` findings are returned.
        """
        # Filter static/CDN URLs up front before spawning threads
        scannable_urls = [
            url for url in urls
            if not self.prefilter.should_skip(url)
        ]

        logger.info(
            f"SmartDetectionEngine: scanning {len(scannable_urls)} URLs "
            f"({len(urls) - len(scannable_urls)} skipped by pre-filter)"
        )

        all_findings = []

        # Process each URL concurrently
        with ThreadPoolExecutor(max_workers=_URL_WORKERS) as executor:
            futures = {
                executor.submit(self._scan_url, url, forms, intelligence): url
                for url in scannable_urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.warning(f"Error scanning URL {url}: {exc}", exc_info=True)

        # Deduplicate by (type, parameter, affected_url)
        unique_findings = self._deduplicate(all_findings)

        logger.info(
            f"SmartDetectionEngine: {len(unique_findings)} findings "
            f"from {len(scannable_urls)} URLs"
        )
        return unique_findings

    def _scan_url(self, url: str, forms: list, intelligence=None) -> list:
        """Scan a single URL with all detectors. Safe to call from a thread."""
        findings = []

        # Each thread gets its own detector instances but shares the SAME HTTP session
        detectors = [cls(session=self._shared_session) for cls in self.detector_classes]
        if intelligence:
            for d in detectors:
                d.intelligence = intelligence

        # Extract parameters
        url_forms = self._forms_for_url(url, forms) if forms else None
        param_info = self.prefilter.extract_parameters(url, url_forms)

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Run detectors on GET params
        get_params = param_info["get_params"]
        if get_params:
            for detector in detectors:
                try:
                    for f in detector.detect(base_url, get_params):
                        f["affected_url"] = url
                        findings.append(f)
                except Exception as exc:
                    logger.warning(
                        f"[{detector.__class__.__name__}] Error on {url}: {exc}",
                        exc_info=True,
                    )

        # Run detectors on POST params (from forms)
        for form in param_info.get("post_params", []):
            post_data = {inp["name"]: "test" for inp in form.get("inputs", [])}
            if not post_data:
                continue
            action_url = form.get("action") or base_url
            for detector in detectors:
                try:
                    for f in detector.detect(action_url, post_data):
                        f["affected_url"] = action_url
                        findings.append(f)
                except Exception as exc:
                    logger.warning(
                        f"[{detector.__class__.__name__}] POST error on {action_url}: {exc}",
                        exc_info=True,
                    )

        # Even without params, still run SSRF detector on the URL
        if not get_params:
            try:
                ssrf = SSRFDetector(session=self._shared_session)
                for f in ssrf.detect(base_url, {}):
                    f["affected_url"] = url
                    findings.append(f)
            except Exception as exc:
                logger.warning(f"SSRF check error on {url}: {exc}")

        return findings

   

    @staticmethod
    def _forms_for_url(url: str, forms: list) -> list:
        """Return forms whose source page matches *url*."""
        if not forms:
            return []
        return [f for f in forms if f.get("url") == url]

    @staticmethod
    def _deduplicate(findings: list) -> list:
        """Remove exact duplicate findings (same type + param + url)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("type"), f.get("parameter"), f.get("affected_url"))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
