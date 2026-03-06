
class ProbeGenerator:
    """
    Generates minimal, lightweight probe payloads for initial testing.
    """
    PROBES = {
        "SQLi": ["'", "\"", "')"],
        "XSS": ["\"><x>", "'><y>", "<img src=x>"],
        "SSRF": ["http://127.0.0.1", "http://localhost"],
        "LFI": ["../../", "/etc/passwd"],
        "RCE": ["; sleep 5", "| id", "`id`"]
    }

    def get_probes(self, vuln_type: str) -> list:
        return self.PROBES.get(vuln_type, ["'"])

probe_generator = ProbeGenerator()
