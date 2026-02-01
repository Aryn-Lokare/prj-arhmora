"""
Multi-Factor Confidence Scoring Engine.

Implements a 4-layer confidence model:
- Pattern Confidence (0-30): Detects malicious patterns
- Response Confidence (0-30): Measures response changes
- Exploit Confidence (0-30): Confirms exploit behavior
- Context Confidence (0-10): Adjusts for endpoint context

Total confidence is capped at 100.
"""

import re
import math
from typing import Dict, Tuple
from urllib.parse import urlparse


class MultiFactorConfidenceEngine:
    """Calculate multi-factor confidence scores for vulnerabilities."""

    # Malicious pattern signatures
    SQL_PATTERNS = [
        r"'\s*(OR|AND)\s+\d+\s*=\s*\d+",
        r"--",
        r";\s*",
        r"UNION\s+SELECT",
        r"DROP\s+TABLE",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
    ]
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<img\s+",
        r"<svg\s+",
        r"<iframe",
    ]
    LFI_PATTERNS = [
        r"\.\./",
        r"etc/passwd",
        r"windows/system32",
        r"\.\.\\",
    ]
    CMD_PATTERNS = [
        r";\s*(cat|ls|whoami|id|pwd|dir)",
        r"\|\s*",
        r"`[^`]+`",
        r"\$\([^)]+\)",
    ]

    # SQL error signatures indicating successful injection
    SQL_ERRORS = [
        "mysql_fetch", "sql syntax", "postgresql", "ora-", "microsoft ole db",
        "unclosed quotation", "syntax error", "sqlite_", "sqlstate",
        "you have an error in your sql", "warning: mysql",
    ]

    # OWASP Top 10 2021 mapping
    OWASP_MAPPING = {
        'SQL Injection': 'A03:2021-Injection',
        'SQLi': 'A03:2021-Injection',
        'Reflected XSS': 'A03:2021-Injection',
        'XSS': 'A03:2021-Injection',
        'Cross-Site Scripting': 'A03:2021-Injection',
        'SSRF Risk': 'A10:2021-SSRF',
        'Security Misconfiguration': 'A05:2021-Security Misconfiguration',
        'Cryptographic Failure': 'A02:2021-Cryptographic Failures',
        'Missing Headers': 'A05:2021-Security Misconfiguration',
    }

    def calculate_pattern_confidence(
        self,
        v_type: str,
        payload: str = '',
        url: str = ''
    ) -> int:
        """
        Calculate pattern-based confidence (0-30).
        
        Detects malicious patterns like SQL keywords, XSS payloads, encoding anomalies.
        """
        score = 0
        combined = f"{payload} {url}".lower()

        if v_type in ['SQL Injection', 'SQLi']:
            matches = sum(1 for p in self.SQL_PATTERNS if re.search(p, combined, re.I))
            score = min(30, matches * 7)
        
        elif v_type in ['Reflected XSS', 'XSS', 'Cross-Site Scripting']:
            matches = sum(1 for p in self.XSS_PATTERNS if re.search(p, combined, re.I))
            score = min(30, matches * 6)
        
        elif v_type in ['LFI', 'Path Traversal', 'Local File Inclusion']:
            matches = sum(1 for p in self.LFI_PATTERNS if re.search(p, combined, re.I))
            score = min(30, matches * 10)
        
        elif v_type in ['Command Injection', 'RCE']:
            matches = sum(1 for p in self.CMD_PATTERNS if re.search(p, combined, re.I))
            score = min(30, matches * 8)
        
        else:
            # Default heuristic: entropy and special characters
            entropy = self._calculate_entropy(combined)
            if entropy > 4.5:
                score = min(30, int((entropy - 4.0) * 12))

        return score

    def calculate_response_confidence(
        self,
        baseline_response: Dict = None,
        test_response: Dict = None
    ) -> int:
        """
        Calculate response-based confidence (0-30).
        
        Measures measurable response changes:
        - HTTP status variation
        - Response length deviation
        - Error messages or stack traces
        - Redirect anomalies
        """
        if not baseline_response or not test_response:
            return 0

        score = 0

        baseline_status = baseline_response.get('status_code', 200)
        test_status = test_response.get('status_code', 200)
        baseline_length = baseline_response.get('content_length', 0)
        test_length = test_response.get('content_length', 0)
        test_body = test_response.get('body', '').lower()

        # Status code change
        if baseline_status != test_status:
            if test_status >= 500:
                score += 15  # Server error - strong indicator
            elif test_status in [302, 301, 403]:
                score += 8
            else:
                score += 5

        # Response length deviation (>20% change)
        if baseline_length > 0:
            length_diff = abs(test_length - baseline_length) / baseline_length
            if length_diff > 0.5:
                score += 10
            elif length_diff > 0.2:
                score += 5

        # Error messages in response
        error_indicators = ['error', 'exception', 'stack trace', 'syntax', 'warning']
        if any(indicator in test_body for indicator in error_indicators):
            score += 6

        # SQL-specific errors
        if any(err in test_body for err in self.SQL_ERRORS):
            score += 10

        return min(30, score)

    def calculate_exploit_confidence(
        self,
        v_type: str,
        validation_result: Dict = None
    ) -> int:
        """
        Calculate exploit-based confidence (0-30).
        
        Awarded when exploit behavior is confirmed:
        - SQL error returned
        - JavaScript execution confirmed
        - Time-based delay verified
        - Unauthorized access achieved
        """
        if not validation_result or not validation_result.get('validated', False):
            return 0

        score = 0
        validation_type = validation_result.get('type', '')

        if validation_type == 'boolean_sqli':
            if validation_result.get('differential_confirmed', False):
                score = 25
        
        elif validation_type == 'time_sqli':
            delay = validation_result.get('delay_ms', 0)
            expected = validation_result.get('expected_delay_ms', 5000)
            if delay >= expected * 0.8:
                score = 30
            elif delay >= expected * 0.5:
                score = 20

        elif validation_type == 'xss_reflection':
            if validation_result.get('unescaped', False):
                score = 30
            elif validation_result.get('payload_reflected', False):
                score = 15

        elif validation_type == 'lfi':
            if validation_result.get('file_content_detected', False):
                score = 30

        elif validation_type == 'command_injection':
            if validation_result.get('output_detected', False):
                score = 30

        return min(30, score)

    def calculate_context_confidence(
        self,
        endpoint_sensitivity: str = 'public',
        is_authenticated: bool = False,
        v_type: str = ''
    ) -> int:
        """
        Calculate context-based confidence adjustment (0-10).
        
        Factors:
        - Authenticated vs unauthenticated endpoints
        - Sensitivity of the resource
        - OWASP Top 10 mapping
        """
        score = 0

        # Endpoint sensitivity
        sensitivity_scores = {
            'admin': 4,
            'auth': 3,
            'data': 3,
            'api': 2,
            'public': 1,
        }
        score += sensitivity_scores.get(endpoint_sensitivity, 1)

        # Authenticated endpoints are higher value targets
        if is_authenticated:
            score += 2

        # Known OWASP Top 10 vulnerability class
        if v_type in self.OWASP_MAPPING:
            score += 3

        return min(10, score)

    def calculate_total_confidence(
        self,
        pattern_conf: int,
        response_conf: int,
        exploit_conf: int,
        context_conf: int
    ) -> Tuple[int, str]:
        """
        Calculate total confidence and classification.
        
        Returns:
            Tuple of (total_confidence, classification)
        
        Classification:
            - 90-100: Confirmed Vulnerability (requires exploit validation)
            - 60-89: Likely Vulnerability
            - 30-59: Suspicious Pattern
            - <30: Informational
        """
        # Sum all layers, capped at 100
        total = min(100, pattern_conf + response_conf + exploit_conf + context_conf)

        # Cannot reach 100% without exploit confirmation
        if exploit_conf < 10 and total >= 100:
            total = 95

        # Cannot be "Confirmed" without actual exploit validation
        if exploit_conf < 15 and total >= 90:
            total = 89

        # Determine classification
        if total >= 90:
            classification = 'confirmed'
        elif total >= 60:
            classification = 'likely'
        elif total >= 30:
            classification = 'suspicious'
        else:
            classification = 'informational'

        return total, classification

    def score_finding(
        self,
        v_type: str,
        url: str = '',
        payload: str = '',
        endpoint_sensitivity: str = 'public',
        baseline_response: Dict = None,
        test_response: Dict = None,
        validation_result: Dict = None,
        is_authenticated: bool = False
    ) -> Dict:
        """
        Calculate complete multi-factor confidence for a finding.
        
        Returns:
            Dict with all confidence scores and classification
        """
        pattern_conf = self.calculate_pattern_confidence(v_type, payload, url)
        response_conf = self.calculate_response_confidence(baseline_response, test_response)
        exploit_conf = self.calculate_exploit_confidence(v_type, validation_result)
        context_conf = self.calculate_context_confidence(endpoint_sensitivity, is_authenticated, v_type)
        
        total_conf, classification = self.calculate_total_confidence(
            pattern_conf, response_conf, exploit_conf, context_conf
        )

        return {
            'pattern_confidence': pattern_conf,
            'response_confidence': response_conf,
            'exploit_confidence': exploit_conf,
            'context_confidence': context_conf,
            'total_confidence': total_conf,
            'classification': classification,
        }

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
