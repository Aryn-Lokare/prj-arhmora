import requests
import logging
from urllib.parse import urlparse, urljoin
import socket
import os
from .ai_model import AIInference

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings = []
        
        # Initialize AI Inference engine
        model_dir = os.path.dirname(os.path.abspath(__file__))
        self.ai_engine = AIInference(model_dir=model_dir)

    def log_finding(self, v_type, url, severity, evidence, remediation):
        self.findings.append({
            'type': v_type,
            'affected_url': url,
            'severity': severity,
            'evidence': evidence,
            'remediation': remediation
        })

    def run_scans(self, crawled_data):
        self.check_security_headers(self.target_url)
        self.check_https(self.target_url)
        self.check_ssrf(self.target_url)
        
        # Test each discovered URL and form
        for url in crawled_data.get('visited_urls', []):
            self.test_sql_injection(url)
            self.test_xss(url)
            self.check_ai_anomaly(url)

        return self.findings

    def check_security_headers(self, url):
        try:
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            missing_headers = []
            if 'Strict-Transport-Security' not in headers:
                missing_headers.append('HSTS')
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('CSP')
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')

            if missing_headers:
                self.log_finding(
                    'Security Misconfiguration',
                    url,
                    'Low',
                    f"Missing security headers: {', '.join(missing_headers)}",
                    "Implement recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)."
                )
            
            # Outdated Components / Version Disclosure
            server = headers.get('Server')
            x_powered_by = headers.get('X-Powered-By')
            if server or x_powered_by:
                evidence = []
                if server: evidence.append(f"Server: {server}")
                if x_powered_by: evidence.append(f"X-Powered-By: {x_powered_by}")
                self.log_finding(
                    'Information Disclosure',
                    url,
                    'Low',
                    f"Version disclosure in headers: {'; '.join(evidence)}",
                    "Remove version information from 'Server' and 'X-Powered-By' headers."
                )

        except Exception as e:
            logger.error(f"Header check error: {e}")

    def check_https(self, url):
        if url.startswith('http://'):
            self.log_finding(
                'Cryptographic Failure',
                url,
                'Medium',
                "Site is using unencrypted HTTP protocol.",
                "Enforce HTTPS and implement HSTS."
            )

    def test_sql_injection(self, url):
        # Basic error-based SQLi check
        payloads = ["'", "''", "\"", "OR 1=1", "';--"]
        parsed = urlparse(url)
        if parsed.query:
            for payload in payloads:
                test_url = url + payload
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    errors = [
                        "mysql_fetch_array()", "you have an error in your sql syntax",
                        "PostgreSQL query failed", "Microsoft OLE DB Provider for SQL Server"
                    ]
                    for error in errors:
                        if error.lower() in response.text.lower():
                            self.log_finding(
                                'SQL Injection',
                                url,
                                'High',
                                f"Possible error-based SQLi detected with payload: {payload}",
                                "Use parameterized queries or ORMs to prevent SQL injection."
                            )
                            return
                except:
                    continue

    def test_xss(self, url):
        # Basic Reflected XSS check
        payload = "<script>alert('XSS')</script>"
        parsed = urlparse(url)
        if parsed.query:
            # This is a very simplified check
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if payload in response.text:
                    self.log_finding(
                        'Reflected XSS',
                        url,
                        'Medium',
                        f"Reflected payload found in response: {payload}",
                        "Sanitize and encode all user-supplied input before rendering it in the browser."
                    )
            except:
                pass

    def check_ssrf(self, target_url):
        # SSRF Protection Check: Check if target URL resolves to an internal IP
        try:
            hostname = urlparse(target_url).hostname
            if hostname:
                ip = socket.gethostbyname(hostname)
                if ip.startswith(('127.', '10.', '172.16.', '192.168.', '0.')):
                    self.log_finding(
                        'SSRF Risk',
                        target_url,
                        'High',
                        f"Target URL resolves to internal IP: {ip}",
                        "Ensure the application does not allow scanning internal network resources."
                    )
        except Exception as e:
            logger.error(f"SSRF check error: {e}")
    def check_ai_anomaly(self, url):
        """Uses AI model to detect suspicious patterns in the URL."""
        if not self.ai_engine.loaded:
            return

        malicious_prob = self.ai_engine.predict(url)
        severity = self.ai_engine.calculate_severity(malicious_prob)
        
        if severity != "Info":
            self.log_finding(
                'AI-Detected Anomaly',
                url,
                severity,
                f"AI model flagged this URL as suspicious (Confidence: {malicious_prob:.2%})",
                "Review the URL for unusual character distributions or patterns common in injection attacks that might bypass traditional rules."
            )
