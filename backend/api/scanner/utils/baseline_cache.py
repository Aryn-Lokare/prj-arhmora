
import hashlib

class BaselineCache:
    """
    Avoid duplicate baseline requests by caching response metadata.
    Key: (url, parameter) or (url, "__headers__")
    """
    def __init__(self):
        self._cache = {}

    def get(self, url: str, parameter: str = "__base__"):
        key = self._generate_key(url, parameter)
        return self._cache.get(key)

    def set(self, url: str, parameter: str, response_data: dict):
        """
        Store response_data: {
            "status_code": int,
            "response_time": float,
            "body_hash": str
        }
        """
        key = self._generate_key(url, parameter)
        self._cache[key] = response_data

    def _generate_key(self, url: str, parameter: str):
        raw = f"{url}|{parameter}"
        return hashlib.md5(raw.encode()).hexdigest()

# Global instance for thread/worker-safe usage within a single process
baseline_cache = BaselineCache()
