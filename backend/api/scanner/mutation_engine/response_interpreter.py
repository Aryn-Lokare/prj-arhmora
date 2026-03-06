
import re

class ResponseInterpreter:
    """
    Analyzes server responses to detect signals of vulnerability.
    """
    
    SQL_ERRORS = [
        r"syntax error", r"mysql_fetch", r"postgres error", r"odbc error",
        r"sqlite3.error", r"oracle error", r"dynamic sql error"
    ]

    def analyze(self, response: dict, probe: str, baseline: dict = None) -> dict:
        """
        Returns signals: {"error_detected": bool, "reflection": bool, "behavior_change": bool}
        """
        signals = {
            "error_detected": False,
            "reflection": False,
            "behavior_change": False,
            "latency_shift": False
        }
        
        body = response.get("body", "").lower()
        
        # 1. Error Detection
        for err in self.SQL_ERRORS:
            if re.search(err, body):
                signals["error_detected"] = True
                break
        
        # 2. Reflection Detection
        if probe.lower() in body:
            signals["reflection"] = True
            
        # 3. Behavior Change (Status Code or Hash)
        if baseline:
            if response.get("status_code") != baseline.get("status_code"):
                signals["behavior_change"] = True
            if response.get("body_hash") != baseline.get("body_hash"):
                signals["behavior_change"] = True
            
            # 4. Latency Shift
            if response.get("response_time", 0) > (baseline.get("response_time", 0) + 3):
                signals["latency_shift"] = True

        return signals

interpreter = ResponseInterpreter()
