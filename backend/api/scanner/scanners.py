import requests
import logging
from urllib.parse import urlparse, urljoin
import socket
import os
from .ai_model import AIInference
from .feature_extractor import FeatureExtractor
from .fix_prioritizer import FixPrioritizer
from .confidence_engine import MultiFactorConfidenceEngine
from .gemini_explainer import GeminiExplainer
from .decision_fusion import (
    DecisionFusionEngine,
    create_rule_result,
    create_ai_result,
    create_context_result,
    Verdict,
)

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
        self.confidence_engine = MultiFactorConfidenceEngine()
        self.gemini_explainer = GeminiExplainer()
        self.fusion_engine = DecisionFusionEngine()  # Decision Fusion Layer

    def log_finding(self, v_type, url, severity, evidence, remediation,
                   risk_score=0, endpoint_sensitivity='public',
                   remediation_simple='', remediation_technical='',
                   pattern_confidence=0, response_confidence=0, 
                   exploit_confidence=0, context_confidence=0,
                   use_ai_explanation=True,
                   ai_classification='', ai_confidence=0.0, detection_method='rule'):
        """
        Log a vulnerability finding with multi-factor confidence scoring.
        
        Args:
            use_ai_explanation: If True, generate AI-powered explanations via Gemini.
                              Falls back to provided/default text if Gemini unavailable.
            ai_classification: AI model's classification of the vulnerability
            ai_confidence: AI model's confidence score (0-1)
            detection_method: 'rule' or 'ai'
        """
        # Generate AI-powered explanations if enabled
        explanation_simple = ''
        explanation_technical = ''
        
        if use_ai_explanation and self.gemini_explainer.enabled:
            try:
                ai_result = self.gemini_explainer.generate_explanation(
                    finding_type=v_type,
                    url=url,
                    severity=severity,
                    evidence=evidence,
                    risk_score=risk_score
                )
                
                # Use AI-generated explanations
                explanation_simple = ai_result.get('explanation_simple', '')
                explanation_technical = ai_result.get('explanation_technical', '')
                
                # Override remediation with AI-generated if not explicitly provided
                if not remediation_simple or remediation_simple == remediation:
                    remediation_simple = ai_result.get('remediation_simple', remediation)
                if not remediation_technical or remediation_technical == remediation:
                    remediation_technical = ai_result.get('remediation_technical', remediation)
                    
            except Exception as e:
                logger.warning(f"AI explanation generation failed: {e}. Using fallback.")
        
        # Fallback if AI explanation not generated
        if not explanation_simple:
            explanation_simple = evidence  # Use evidence as fallback
        if not explanation_technical:
            explanation_technical = evidence
        if not remediation_simple:
            remediation_simple = remediation
        if not remediation_technical:
            remediation_technical = remediation

        # Calculate context confidence if not provided
        if context_confidence == 0:
            context_confidence = self.confidence_engine.calculate_context_confidence(
                endpoint_sensitivity, is_authenticated=False, v_type=v_type
            )
        
        # Calculate total confidence and classification
        total_confidence, classification = self.confidence_engine.calculate_total_confidence(
            pattern_confidence, response_confidence, exploit_confidence, context_confidence
        )

        self.findings.append({
            'type': v_type,
            'affected_url': url,
            'severity': severity,
            'evidence': evidence,
            # AI-generated explanations (non-technical and technical)
            'explanation_simple': explanation_simple,
            'explanation_technical': explanation_technical,
            'remediation': remediation,
            'remediation_simple': remediation_simple,
            'remediation_technical': remediation_technical,
            'risk_score': risk_score,
            'endpoint_sensitivity': endpoint_sensitivity,
            # Multi-factor confidence
            'pattern_confidence': pattern_confidence,
            'response_confidence': response_confidence,
            'exploit_confidence': exploit_confidence,
            'context_confidence': context_confidence,
            'total_confidence': total_confidence,
            'confidence': total_confidence,  # Backward compatibility
            'classification': classification,
            # AI ML Classification
            'ai_classification': ai_classification,
            'ai_confidence': ai_confidence,
            'detection_method': detection_method,
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
                    endpoint_sensitivity='public',
                    remediation_simple="Your website is missing improved security instructions (headers) that tell browsers how to protect your users from common attacks.",
                    remediation_technical=f"Configure the web server to send missing headers: {', '.join(missing_headers)}.",
                    pattern_confidence=25,  # Clear pattern match
                    response_confidence=0   # No response manipulation needed
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
                    endpoint_sensitivity='public',
                    remediation_simple="Your server is revealing its exact software version, which helps attackers search for known weaknesses.",
                    remediation_technical="Disable server tokens/signatures in web server config (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx) and remove 'X-Powered-By' header.",
                    pattern_confidence=20
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
                endpoint_sensitivity='public',
                remediation_simple="Your website connection is not secure (HTTP). Attackers can intercept passwords and data sent by your users.",
                remediation_technical="Obtain an SSL/TLS certificate and configure 301 redirects from HTTP to HTTPS. Implement HSTS header.",
                pattern_confidence=30  # Definitive pattern
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
                                endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(url),
                                remediation_simple="Attackers could trick your database into revealing secret information by manipulating input fields.",
                                remediation_technical="Input validation error allowing SQLi. Use parameterized queries (prepared statements) instead of string concatenation for SQL queries.",
                                pattern_confidence=25,   # SQL pattern detected
                                response_confidence=30,  # SQL error in response
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
                        endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(url),
                        remediation_simple="Attackers could plant malicious scripts on your page to steal user data or perform actions on their behalf.",
                        remediation_technical="Reflected Cross-Site Scripting (XSS). Output encode all user input using context-appropriate escaping (HTML, JS, URL) before rendering.",
                        pattern_confidence=20,   # XSS pattern
                        response_confidence=25,  # Payload reflected in response
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
                        endpoint_sensitivity=self.feature_extractor.get_endpoint_sensitivity_label(target_url),
                        remediation_simple="Attackers could use your server to access or spy on your internal private network.",
                        remediation_technical="Server-Side Request Forgery (SSRF). Whitelist permitted domains/IPs. Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).",
                        pattern_confidence=30  # Internal IP confirmed
                    )
        except Exception as e:
            logger.error(f"SSRF check error: {e}")

    def check_ai_anomaly(self, url):
        """Uses AI model to detect suspicious patterns in the URL using the enhanced multi-class classifier."""
        # 1. Get binary/anomaly analysis (legacy + context validaton)
        result = self.ai_engine.analyze_url(url)
        
        # 2. Get specific classification (new multi-class model)
        classification = self.ai_engine.classify_vulnerability(url)
        
        # Determine if we should log this finding
        should_log = False
        
        # Logic:
        # - If binary model says High/Medium Risk, we log it.
        # - If multi-class model says it's a specific attack with high confidence, we log it.
        # - If multi-class model says it's NORMAL with high confidence, we suppress it (even if binary alert).
        
        is_high_risk = result['severity'] in ['High', 'Medium'] or result['action'] in ['block', 'throttle']
        is_specific_attack = classification['class'] > 0 and classification['confidence'] > 0.6
        is_confident_normal = classification['class'] == 0 and classification['confidence'] > 0.8
        
        if (is_high_risk or is_specific_attack) and not is_confident_normal:
            should_log = True
            
        if should_log:
            # Use specific class name if available, otherwise generic
            if classification['class'] > 0:
                vuln_type = f"AI-Detected {classification['class_name']}"
                pattern_conf = int(classification['confidence'] * 30)
            else:
                vuln_type = "AI-Detected Anomaly"
                pattern_conf = int(result.get('threat_confidence', result['confidence']) * 30)

            # Construct message
            anomaly_score = result.get('anomaly_score', 0)
            class_conf = classification['confidence']
            
            if classification['class'] > 0:
                msg = f"AI model classified this as {classification['class_name']} with {class_conf:.1%} confidence."
                simple_msg = f"Our AI checks suggest this is a {classification['class_name']} attack."
                tech_remediation = f"AI detected {classification['class_name']} patterns. Investigate and apply specific mitigations for this vulnerability class."
            else:
                msg = f"AI detected unusual characteristics (Anomaly: {anomaly_score:.1f})."
                simple_msg = "Our AI found this URL looks unusual, but we haven't confirmed it's an attack."
                tech_remediation = "AI Anomaly Detection. Investigate request logs. Consider rate-limiting suspicious sources."

            self.log_finding(
                vuln_type,
                url,
                result['severity'],
                msg,
                "Review the URL for unusual character distributions or patterns.",
                risk_score=result['risk_score'],
                endpoint_sensitivity=result['endpoint_sensitivity'],
                remediation_simple=simple_msg,
                remediation_technical=tech_remediation,
                pattern_confidence=pattern_conf,
                # New fields (need to update log_finding signature)
                ai_classification=classification['class_name'],
                ai_confidence=classification['confidence'],
                detection_method='ai'
            )
