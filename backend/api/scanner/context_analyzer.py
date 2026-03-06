
import re

class ContextAnalyzer:
    """
    Analyzes URL context and parameter names to prioritize detectors.
    """
    
    # Priority groups
    PRIORITY_RULES = {
        "SQLi": [r"id$", r"user", r"account", r"order", r"sort", r"search", r"query"],
        "SSRF": [r"url$", r"redirect", r"callback", r"dest", r"webhook", r"api", r"src"],
        "XSS": [r"q$", r"search", r"query", r"name", r"title", r"msg", r"comment"],
        "LFI": [r"file", r"path", r"doc", r"page", r"template", r"include"],
        "RCE": [r"cmd", r"exec", r"eval", r"upload", r"script", r"command"]
    }

    def analyze(self, parameter: str) -> dict:
        """
        Calculates priority scores (0.0 to 1.0) for each vulnerability class.
        """
        parameter = parameter.lower()
        scores = {
            "SQLi": 0.3, # Baseline
            "XSS": 0.3,
            "SSRF": 0.2,
            "LFI": 0.2,
            "RCE": 0.1
        }

        for vuln, patterns in self.PRIORITY_RULES.items():
            for pattern in patterns:
                if re.search(pattern, parameter):
                    scores[vuln] = min(0.9, scores[vuln] + 0.4)
                    break
        
        return scores

analyzer = ContextAnalyzer()
