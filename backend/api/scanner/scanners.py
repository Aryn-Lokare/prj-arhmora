import requests
import logging
from urllib.parse import urlparse, urljoin
import socket
import os
from .ai_model import AIInference
from .feature_extractor import FeatureExtractor
from .fix_prioritizer import FixPrioritizer

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings = []
        
        # Initialize AI Inference engine and enhanced modules
        model_dir = os.path.dirname(os.path.abspath(__file__))
        self.ai_engine = AIInference(model_dir=model_dir)
        self.feature_extractor = FeatureExtractor()
        self.prioritizer = FixPrioritizer()

    def log_finding(self, v_type, url, severity, evidence, remediation,
                   risk_score=0, confidence=0.0, action='flagged', priority_rank=None, endpoint_sensitivity='public',
                   remediation_simple='', remediation_technical=''):
        
        # Fallback if specific dual-tone not provided but single remediation is
        if not remediation_simple:
            remediation_simple = remediation
        if not remediation_technical:
            remediation_technical = remediation

        self.findings.append({
            'type': v_type,
            'affected_url': url,
            'severity': severity,
            'evidence': evidence,
            'remediation': remediation, # Keep legacy field populated
            'remediation_simple': remediation_simple,
            'remediation_technical': remediation_technical,
            'risk_score': risk_score,
            'confidence': confidence,
            'action_taken': action,
            'endpoint_sensitivity': endpoint_sensitivity,
            # priority_rank will be calculated at the end
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

        # Prioritize findings before returning
        self.findings = self.prioritizer.rank_findings(self.findings)
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
                    "Implement recommended security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
                    risk_score=20,
                    confidence=1.0,
                    endpoint_sensitivity='public',
                    remediation_simple="Your website is missing improved security instructions (headers) that tell browsers how to protect your users from common attacks.",
                    remediation_technical=f"Configure the web server to send missing headers: {', '.join(missing_headers)}."
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
                    "Remove version information from 'Server' and 'X-Powered-By' headers.",
                    risk_score=15,
                    confidence=1.0,
                    endpoint_sensitivity='public',
                    remediation_simple="Your server is revealing its exact software version, which helps attackers search for known weaknesses.",
                    remediation_technical="Disable server tokens/signatures in web server config (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx) and remove 'X-Powered-By' header."
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
                "Enforce HTTPS and implement HSTS.",
                risk_score=40,
                confidence=1.0,
                endpoint_sensitivity='public',
                remediation_simple="Your website connection is not secure (HTTP). Attackers can intercept passwords and data sent by your users.",
                remediation_technical="Obtain an SSL/TLS certificate and configure 301 redirects from HTTP to HTTPS. Implement HSTS header."
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
                                "Use parameterized queries or ORMs to prevent SQL injection.",
                                risk_score=90,
                                confidence=0.95,
                                action='block',
                                endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(url),
                                remediation_simple="Attackers could trick your database into revealing secret information by manipulating input fields.",
                                remediation_technical="Input validation error allowing SQLi. Use parameterized queries (prepared statements) instead of string concatenation for SQL queries."
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
                        "Sanitize and encode all user-supplied input before rendering it in the browser.",
                        risk_score=70,
                        confidence=0.90,
                        action='block',
                        endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(url),
                        remediation_simple="Attackers could plant malicious scripts on your page to steal user data or perform actions on their behalf.",
                        remediation_technical="Reflected Cross-Site Scripting (XSS). Output encode all user input using context-appropriate escaping (HTML, JS, URL) before rendering."
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
                        "Ensure the application does not allow scanning internal network resources.",
                        risk_score=85,
                        confidence=1.0,
                        endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(target_url),
                        remediation_simple="Attackers could use your server to access or spy on your internal private network.",
                        remediation_technical="Server-Side Request Forgery (SSRF). Whitelist permitted domains/IPs. Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)."
                    )
        except Exception as e:
            logger.error(f"SSRF check error: {e}")

    def check_ai_anomaly(self, url):
        """Uses AI model to detect suspicious patterns in the URL."""
        # Use the comprehensive analyze_url method
        result = self.ai_engine.analyze_url(url)
        
        # Log if risk is significant (Medium/High) or Action is Block/Throttle
        if result['severity'] in ['High', 'Medium'] or result['action'] in ['block', 'throttle']:
            self.log_finding(
                'AI-Detected Anomaly',
                url,
                result['severity'],
                f"AI model flagged this URL as suspicious (Risk: {result['risk_score']}, Confidence: {result['confidence']:.2%})",
                "Review the URL for unusual character distributions or patterns common in injection attacks that might bypass traditional rules.",
                risk_score=result['risk_score'],
                confidence=result['confidence'],
                action=result['action'],
                endpoint_sensitivity=result['endpoint_sensitivity'],
                remediation_simple="Our AI detected suspicious patterns in this URL that look like an automated attack attempt.",
                remediation_technical="AI Anomaly Detection. Investigate request logs for this URL pattern. Consider rate-limiting or blocking source IP if pattern matches known attack signatures."
            )
