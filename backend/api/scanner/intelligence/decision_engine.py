import logging
from . import framework_detector, learning_store, payload_optimizer, exploit_chain

logger = logging.getLogger(__name__)

class DecisionEngine:
    """
    Coordinator for the Adaptive AI Decision Intelligence Layer.
    Integrates framework detection, learning store, and exploit chaining.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.framework = "Unknown"
        self._payload_cache = {} # Cache: {vuln_type: [payloads]}
        self._prefetched = False

    def _prefetch_history(self):
        """Fetch all successful payloads for this target once."""
        if self._prefetched:
            return
        try:
            history = learning_store.get_history(self.target_url)
            # Organise by vuln_type for faster access if learning_store supports it
            # For now, we'll just store the flat list if it's small
            self._payload_cache["__all__"] = history
            self._prefetched = True
        except Exception as e:
            logger.error(f"History prefetch failed: {e}")

    def run_framework_detection(self, headers: dict, body: str):
        """Detect and store site framework."""
        self.framework = framework_detector.detect_framework(headers, body)
        logger.info(f"Target Framework Detected: {self.framework}")
        return self.framework

    def optimize_payloads(self, vuln_type: str, default_payloads: list) -> list:
        """Get prioritized payloads using cached history."""
        if not self._prefetched:
            self._prefetch_history()
            
        history = self._payload_cache.get("__all__", [])
        # Simple filtering for this vuln_type if possible, or just use all
        # For efficiency, we return history + defaults
        return history + [p for p in default_payloads if p not in history]

    def record_finding(self, finding: dict):
        """Log a confirmed finding for future learning."""
        learning_store.record_finding(self.target_url, finding, framework=self.framework)

    def analyze_chains(self, confirmed_findings: list) -> str:
        """Analyze confirmed findings for compound exploit chains."""
        return exploit_chain.predict_chain(confirmed_findings)
