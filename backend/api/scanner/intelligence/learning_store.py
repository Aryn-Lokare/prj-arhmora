import hashlib
import logging
from api.models import DiscoveryMemory

logger = logging.getLogger(__name__)

def hash_target(url: str) -> str:
    """Generate SHA256 hash of the target URL for indexing."""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def record_finding(url, finding, framework=None):
    """
    Persist a successful vulnerability discovery.
    Coordinates with DecisionEngine.
    """
    try:
        DiscoveryMemory.objects.create(
            target_hash=hash_target(url),
            endpoint=finding.get("affected_url", url),
            parameter=finding.get("parameter", "N/A"),
            vuln_type=finding.get("type", "Unknown"),
            framework=framework,
            payload_used=finding.get("evidence", {}).get("payload", ""),
            success=True
        )
    except Exception as e:
        logger.error(f"Failed to record finding to ScanMemory: {e}")

def get_history(url, vuln_type=None):
    """Retrieve historical successful payloads for a target."""
    target_h = hash_target(url)
    queryset = DiscoveryMemory.objects.filter(target_hash=target_h, success=True)
    if vuln_type:
        queryset = queryset.filter(vuln_type=vuln_type)
    
    return list(queryset.values_list('payload_used', flat=True).distinct())
