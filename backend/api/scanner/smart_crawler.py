"""
Smart Crawler — Armora v2.

Auto-detects the best crawl strategy for the target:
- Tries Playwright (headless browser) first for JS-rendered SPAs.
- Falls back to the static requests-based Crawler if Playwright
  is unavailable or fails.

This means the scanner works correctly on:
  - Traditional server-rendered apps  → static crawler (fast)
  - Next.js / React / Vue / Angular   → Playwright crawler (full DOM)
"""

import logging

logger = logging.getLogger(__name__)


class SmartCrawler:
    """
    Thin wrapper that picks the right crawler automatically.

    Usage::

        crawler = SmartCrawler("https://example.com", max_pages=15)
        data = crawler.crawl()
    """

    def __init__(self, base_url: str, max_pages: int = 15):
        self.base_url = base_url
        self.max_pages = max_pages

    def crawl(self) -> dict:
        """
        Attempt Playwright-based crawl; fall back to static crawler.

        Returns:
            {
                "visited_urls": [str, ...],
                "forms":        [form_dict, ...],
                "params":       [str, ...],
            }
        """
        # --- Try Playwright first ---
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401 (import test)
            from .playwright_crawler import PlaywrightCrawler

            logger.info("[SmartCrawler] Using Playwright (headless browser) for crawl.")
            result = PlaywrightCrawler(self.base_url, max_pages=self.max_pages).crawl()

            # If Playwright found nothing useful, fall back to static
            if not result.get("visited_urls"):
                logger.warning("[SmartCrawler] Playwright returned no URLs — falling back to static crawler.")
                return self._static_crawl()

            return result

        except ImportError:
            logger.warning(
                "[SmartCrawler] Playwright not installed — falling back to static crawler. "
                "Run: playwright install chromium"
            )
        except Exception as exc:
            logger.warning(
                f"[SmartCrawler] Playwright crawl failed ({exc}) — falling back to static crawler."
            )

        return self._static_crawl()

    def _static_crawl(self) -> dict:
        """Run the legacy requests-based crawler."""
        from .crawler import Crawler
        logger.info("[SmartCrawler] Using static (requests) crawler.")
        return Crawler(self.base_url, max_pages=self.max_pages).crawl()
