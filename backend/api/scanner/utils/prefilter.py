"""
Pre-Filter — Armora v2.

Skips static resources, CDN endpoints, and extracts injection vectors
(GET / POST parameters) from URLs and crawled form data.
"""

import logging
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# File extensions that are always static and never injectable.
STATIC_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".js", ".map", ".webp", ".avif", ".bmp",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav",
}

# Known CDN / analytics hostnames to skip.
CDN_HOSTNAMES = {
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "unpkg.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
}


class PreFilter:
    """Gate-keeper that decides which URLs deserve active testing."""

    @staticmethod
    def should_skip(url: str) -> bool:
        """
        Return ``True`` if *url* should be skipped (static or CDN).
        """
        parsed = urlparse(url)

        # Skip known CDN hosts
        if parsed.hostname and parsed.hostname.lower() in CDN_HOSTNAMES:
            return True

        # Skip static file extensions
        path_lower = parsed.path.lower()
        for ext in STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True

        return False

    @staticmethod
    def extract_parameters(url: str, forms: list = None) -> dict:
        """
        Extract injectable parameters from *url* query string and
        optional *forms* data (as returned by the Crawler).

        Returns:
            {
                "get_params": {"key": "value", ...},
                "post_params": [
                    {"action": str, "method": str, "inputs": [{"name": str, "type": str}]}
                ],
                "has_injection_vectors": bool,
            }
        """
        parsed = urlparse(url)
        get_params = {}
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            get_params[key] = values[0] if values else ""

        post_params = []
        if forms:
            for form in forms:
                if form.get("inputs"):
                    post_params.append({
                        "action": form.get("action", ""),
                        "method": form.get("method", "post"),
                        "inputs": form.get("inputs", []),
                    })

        has_vectors = bool(get_params) or bool(post_params)

        return {
            "get_params": get_params,
            "post_params": post_params,
            "has_injection_vectors": has_vectors,
        }
