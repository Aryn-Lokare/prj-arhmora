"""
Playwright Crawler — Armora v2.

Uses a headless Chromium browser to crawl JavaScript-rendered SPAs
(Next.js, React, Vue, Angular, etc.).
"""

import logging
from urllib.parse import urljoin, urlparse
from .utils.prefilter import PreFilter

logger = logging.getLogger(__name__)


class PlaywrightCrawler:
    """
    Headless-browser crawler for JS-rendered SPAs.
    """

    def __init__(self, base_url: str, max_pages: int = 15):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.prefilter = PreFilter()

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    def crawl(self) -> dict:
        """
        Launch a headless browser and crawl the target.
        """
        from playwright.sync_api import sync_playwright

        visited_urls: set[str] = set()
        urls_to_visit: list[str] = [self.base_url]
        discovered_forms: list[dict] = []
        discovered_params: set[str] = set()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            context = browser.new_context(
                user_agent="Armora-Scanner/2.0",
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            page = context.new_page()

            while urls_to_visit and len(visited_urls) < self.max_pages:
                url = urls_to_visit.pop(0)
                clean_url = self._strip_fragment(url)

                if clean_url in visited_urls:
                    continue
                if not self._is_same_domain(clean_url):
                    continue
                if self.prefilter.should_skip(clean_url):
                    continue

                try:
                    logger.info(f"[Playwright] Crawling: {clean_url}")

                    page.goto(
                        clean_url,
                        wait_until="domcontentloaded",
                        timeout=5000,
                    )

                    visited_urls.add(clean_url)

                    # --- Extract links ---
                    hrefs = page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href)",
                    )
                    for href in hrefs:
                        candidate = self._strip_fragment(href)
                        if self._is_same_domain(candidate) and candidate not in visited_urls:
                            if not self.prefilter.should_skip(candidate):
                                urls_to_visit.append(candidate)

                    # --- Extract forms ---
                    forms_data = page.evaluate("""() => {
                        const forms = [];
                        document.querySelectorAll('form').forEach(form => {
                            const inputs = [];
                            form.querySelectorAll('input, textarea, select').forEach(el => {
                                if (el.name) {
                                    inputs.push({ name: el.name, type: el.type || 'text' });
                                }
                            });
                            forms.push({
                                action: form.action || '',
                                method: (form.method || 'get').toLowerCase(),
                                inputs: inputs,
                            });
                        });
                        return forms;
                    }""")

                    for form in forms_data:
                        form["url"] = clean_url
                        discovered_forms.append(form)
                        for inp in form.get("inputs", []):
                            discovered_params.add(inp["name"])

                    # --- Discover query params ---
                    parsed = urlparse(page.url)
                    if parsed.query:
                        for part in parsed.query.split("&"):
                            if "=" in part:
                                discovered_params.add(part.split("=")[0])

                except Exception as exc:
                    logger.warning(f"[Playwright] Error crawling {clean_url}: {exc}")
                    visited_urls.add(clean_url)

            context.close()
            browser.close()

        return {
            "visited_urls": list(visited_urls),
            "forms": discovered_forms,
            "params": list(discovered_params),
        }

    def _is_same_domain(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    @staticmethod
    def _strip_fragment(url: str) -> str:
        return url.split("#")[0].rstrip("/") or url
