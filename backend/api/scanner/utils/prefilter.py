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
    def should_scan(url: str) -> bool:
        """
        Return ``True`` if *url* should be scanned. 
        Skips static resources and irrelevant directories.
        """
        if not url:
            return False
            
        parsed = urlparse(url.lower())
        path = parsed.path
        
        # 1. Skip Resources
        skip_extensions = {
            '.css', '.js', '.png', '.jpg', '.jpeg', '.svg', 
            '.ico', '.woff', '.ttf', '.map', '.gif', '.pdf',
            '.woff2', '.eot', '.otf', '.webp', '.avif', '.mp4'
        }
        if any(path.endswith(ext) for ext in skip_extensions):
            return False
            
        # 2. Skip Directories
        skip_dirs = {
            '/assets/', '/static/', '/images/', '/fonts/', '/media/', '/vendor/'
        }
        if any(sd in path for sd in skip_dirs):
            return False
            
        # 3. Skip known CDN hosts
        if parsed.hostname and parsed.hostname in CDN_HOSTNAMES:
            return False
            
        return True

    @staticmethod
    def extract_parameters(url: str, forms: list = None) -> dict:
        """
        Extract injectable parameters from GET and POST vectors.
        Returns: {"url": "...", "get_params": {"id": "1"}, "post_params": [{"action": "...", "inputs": [...]}]}
        """
        parsed = urlparse(url)
        get_params = {}
        
        # GET Params
        for key, values in parse_qs(parsed.query).items():
            get_params[key] = values[0] if values else "test"

        # POST Params (from forms)
        post_params = forms if forms else []

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return {
            "url": base_url,
            "get_params": get_params,
            "post_params": post_params
        }
