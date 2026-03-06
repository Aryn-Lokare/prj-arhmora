
import logging
from ..utils.baseline_cache import baseline_cache
from .probe_generator import probe_generator
from .response_interpreter import interpreter
from .payload_mutator import mutator

logger = logging.getLogger(__name__)

class AdaptivePayloadEngine:
    """
    Orchestrates the Probe -> Analyze -> Mutate -> Verify flow.
    """
    
    def __init__(self, http_client):
        self.http_client = http_client

    async def scan_parameter(self, url: str, parameter: str, vuln_type: str, method: str = "GET") -> list:
        """
        Executes an adaptive scan for a specific parameter.
        Returns a list of confirmed findings.
        """
        findings = []
        
        # 1. Get/Set Baseline
        baseline = baseline_cache.get(url, parameter)
        if not baseline:
            baseline = await self.http_client.send_request(url, method=method)
            baseline_cache.set(url, parameter, baseline)

        # 2. Probe Phase
        probes = probe_generator.get_probes(vuln_type)
        for probe in probes:
            params = {parameter: probe} if method == "GET" else None
            data = {parameter: probe} if method == "POST" else None
            
            response = await self.http_client.send_request(url, method=method, params=params, data=data)
            signals = interpreter.analyze(response, probe, baseline)
            
            if any(signals.values()):
                # 3. Mutation Phase
                mutated_payloads = mutator.mutate(vuln_type, signals)
                for payload in mutated_payloads:
                    m_params = {parameter: payload} if method == "GET" else None
                    m_data = {parameter: payload} if method == "POST" else None
                    
                    m_response = await self.http_client.send_request(url, method=method, params=m_params, data=m_data)
                    m_signals = interpreter.analyze(m_response, payload, baseline)
                    
                    # 4. Verification Phase
                    if self._verify_exploit(vuln_type, m_signals, m_response, payload):
                        findings.append({
                            "type": vuln_type,
                            "parameter": parameter,
                            "payload": payload,
                            "status": "Confirmed",
                            "confidence": 1.0
                        })
                        break # Exploit confirmed, no need for more payloads for this class
                        
            if findings: break # Stop probing if already confirmed

        return findings

    def _verify_exploit(self, vuln_type: str, signals: dict, response: dict, payload: str) -> bool:
        """
        Strict exploit verification logic.
        """
        if vuln_type == "SQLi":
            return signals.get("error_detected") or signals.get("latency_shift")
        if vuln_type == "XSS":
            return signals.get("reflection") and ("alert(1)" in response.get("body", ""))
        if vuln_type == "SSRF":
            return "ami-id" in response.get("body", "") or "local-hostname" in response.get("body", "") or response.get("status_code") == 200
        if vuln_type == "LFI":
            return "root:x:0:0" in response.get("body", "")
        if vuln_type == "RCE":
            return "uid=" in response.get("body", "") or "groups=" in response.get("body", "")
            
        return False
