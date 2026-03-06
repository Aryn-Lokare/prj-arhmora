import secrets
import logging
import requests
from django.conf import settings
from decouple import config

logger = logging.getLogger(__name__)

class OOBManager:
    """
    Manages Out-of-band (OOB) interactions for blind vulnerability detection.
    
    Supports:
    1. Token generation.
    2. Payload construction.
    3. Interaction polling (OAST).
    """

    def __init__(self):
        self.oob_domain = config('OOB_DOMAIN', default='oob.arhmora.com')
        # This would be an internal API key for the Arhmora Interaction Server
        self.api_key = config('OOB_API_KEY', default='')
        self.poll_url = f"https://api.{self.oob_domain}/interactions"

    def generate_token(self, length=16) -> str:
        """Generate a unique tracking token."""
        return secrets.token_hex(length // 2)

    def get_http_payload(self, token: str) -> str:
        """Construct an OOB HTTP payload."""
        return f"http://{token}.{self.oob_domain}"

    def get_dns_payload(self, token: str) -> str:
        """Construct an OOB DNS payload."""
        return f"{token}.{self.oob_domain}"

    def check_interactions(self, token: str) -> bool:
        """
        Poll the OOB server to see if the token was triggered.
        """
        if not self.api_key:
            # Fallback for dev: assume no hits
            return False

        try:
            # Simulated API call to the Interaction Server
            params = {"token": token, "key": self.api_key}
            resp = requests.get(self.poll_url, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("hit_count", 0) > 0
        except Exception as e:
            logger.error(f"OOB Polling failed for token {token}: {e}")
        
        return False

# Singleton instance
oob = OOBManager()
