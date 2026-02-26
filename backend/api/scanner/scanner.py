"""
Armora Scanner — Orchestrator (v2).

Top-level entry point that:
1. Receives a target URL.
2. Runs the pre-filter.
3. Delegates to SmartDetectionEngine (Layer 1).
4. Checks basic security posture (headers, HTTPS).
5. For Confirmed findings → calls GeminiExplainer (Layer 2).
6. Returns a structured JSON-serialisable report.

No ML. No anomaly scoring. No heavy processes.
"""

import logging
import socket
from urllib.parse import urlparse

from .smart_engine import SmartDetectionEngine
from .gemini_explainer import GeminiExplainer
from .utils.http_client import HttpClient
from .utils.confidence import calculate_confidence, classify_confidence
from .intelligence.decision_engine import DecisionEngine

logger = logging.getLogger(__name__)


class ArmoraScanner:
    """
    Armora v2 scanner orchestrator.

    Usage::

        scanner = ArmoraScanner(target_url)
        report  = scanner.run(crawled_data)
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.http = HttpClient()
        self.engine = SmartDetectionEngine()
        self.explainer = GeminiExplainer()
        self.intelligence = DecisionEngine(target_url)

   
    def run(self, crawled_data: dict) -> list:
        """
        Execute the full scan pipeline.

        Args:
            crawled_data: Output of the Crawler, containing
                ``visited_urls``, ``forms``, ``params``.

        Returns:
            List of finding dicts, each enriched with:
            - severity label
            - remediation text
            - Gemini explanation (Confirmed only)
        """
        urls = crawled_data.get("visited_urls", [])
        forms = crawled_data.get("forms", [])

        findings = []

        # --- Layer 1: Smart Detection Engine ---
        raw_findings = self.engine.scan(urls, forms, intelligence=self.intelligence)

        # --- Basic security checks (always run on target URL) ---
        basic_findings, target_resp = self._run_basic_checks(self.target_url)
        raw_findings.extend(basic_findings)

        # Detect Framework using the existing response from basic checks
        if target_resp:
            self.intelligence.run_framework_detection(
                target_resp.get("headers", {}), 
                target_resp.get("body", "")
            )

        # --- Enrich each finding ---
        for finding in raw_findings:
            enriched = self._enrich_finding(finding)
            findings.append(enriched)

        # --- Layer 2: Gemini Explainer (Confirmed only) ---
        confirmed_findings = [f for f in findings if f.get("status") == "Confirmed"]
        
        # --- Intelligence: Exploit Chain Analysis & Persistence ---
        exploit_chain_summary = "No multi-stage exploit chain identified."
        if confirmed_findings:
            # Record findings to memory
            for f in confirmed_findings:
                self.intelligence.record_finding(f)
            
            # Predict chains
            exploit_chain_summary = self.intelligence.analyze_chains(confirmed_findings)
            self._attach_gemini_explanations(confirmed_findings)
        else:
            logger.info("No confirmed findings — skipping Gemini Explainer.")

        logger.info(
            f"ArmoraScanner complete: {len(findings)} findings "
            f"({len(confirmed_findings)} Confirmed)"
        )
        
        # Add intelligence results to the report structure
        report = {
            "findings": findings,
            "intelligence": {
                "framework": self.intelligence.framework,
                "exploit_chain": exploit_chain_summary
            }
        }
        return report # Note: This changes the return type from list to dict. 
                      # I need to check if this breaks anything.

   
    def _run_basic_checks(self, url: str) -> tuple:
        """
        Non-parameter-based checks: security headers, HTTPS, SSRF risk.
        Returns (findings_list, last_response_dict).
        """
        findings = []
        last_resp = None

        # --- Security Headers ---
        try:
            resp = self.http.get(url)
            last_resp = resp
            if resp["status_code"] != 0:
                headers = resp.get("headers", {})
                missing = []
                for hdr in ["Strict-Transport-Security", "X-Frame-Options",
                            "Content-Security-Policy", "X-Content-Type-Options"]:
                    if hdr not in headers:
                        missing.append(hdr)

                if missing:
                    findings.append({
                        "type": "Security Misconfiguration",
                        "parameter": "__headers__",
                        "confidence": calculate_confidence(
                            exploit_success=False,
                            strong_signature=True,
                            server_error=False,
                        ),
                        "status": "Likely",
                        "affected_url": url,
                        "evidence": {
                            "missing_headers": missing,
                            "signatures_matched": [f"Missing: {h}" for h in missing],
                        },
                    })

                # Version disclosure
                server = headers.get("Server", "")
                xpb = headers.get("X-Powered-By", "")
                if server or xpb:
                    disclosed = []
                    if server:
                        disclosed.append(f"Server: {server}")
                    if xpb:
                        disclosed.append(f"X-Powered-By: {xpb}")
                    findings.append({
                        "type": "Information Disclosure",
                        "parameter": "__headers__",
                        "confidence": calculate_confidence(
                            exploit_success=False,
                            strong_signature=True,
                            server_error=False,
                        ),
                        "status": "Likely",
                        "affected_url": url,
                        "evidence": {
                            "disclosed": disclosed,
                            "signatures_matched": disclosed,
                        },
                    })
        except Exception as exc:
            logger.error(f"Header check error: {exc}")

        # --- HTTPS Check ---
        if url.startswith("http://"):
            findings.append({
                "type": "Cryptographic Failure",
                "parameter": "__protocol__",
                "confidence": calculate_confidence(
                    exploit_success=False,
                    strong_signature=True,
                    server_error=False,
                ),
                "status": "Likely",
                "affected_url": url,
                "evidence": {
                    "detail": "Site uses unencrypted HTTP.",
                    "signatures_matched": ["HTTP protocol in use"],
                },
            })

        return findings, last_resp

   

    @staticmethod
    def _enrich_finding(finding: dict) -> dict:
        """Add severity, remediation text based on finding type."""
        vuln_type = finding.get("type", "")

        severity_map = {
            "SQL Injection": "High",
            "Cross-Site Scripting (XSS)": "Medium",
            "Server-Side Request Forgery (SSRF)": "High",
            "Local File Inclusion (LFI)": "High",
            "Remote Code Execution (RCE)": "High",
            "Security Misconfiguration": "Low",
            "Information Disclosure": "Low",
            "Cryptographic Failure": "Medium",
        }

        remediation_map = {
            "SQL Injection": {
                "simple": "Attackers could trick your database into revealing or modifying data by manipulating input fields.",
                "technical": "Use parameterized queries (prepared statements) instead of string concatenation. Apply input validation and least-privilege database access.",
            },
            "Cross-Site Scripting (XSS)": {
                "simple": "Attackers could plant malicious scripts on your page to steal user data.",
                "technical": "Output-encode all user input using context-appropriate escaping (HTML, JS, URL). Implement Content-Security-Policy header.",
            },
            "Server-Side Request Forgery (SSRF)": {
                "simple": "Attackers could use your server to access internal resources or cloud credentials.",
                "technical": "Whitelist permitted domains/IPs. Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). Validate and sanitize all URL inputs.",
            },
            "Local File Inclusion (LFI)": {
                "simple": "Attackers could read sensitive files from your server such as passwords or configuration.",
                "technical": "Never use user input directly in file paths. Use a whitelist of allowed files. Disable PHP wrappers if not needed.",
            },
            "Remote Code Execution (RCE)": {
                "simple": "Attackers could run arbitrary commands on your server, potentially taking full control.",
                "technical": "Never pass user input to OS commands. Use language-native libraries instead of shell commands. Apply strict input validation.",
            },
            "Security Misconfiguration": {
                "simple": "Your website is missing security headers that protect users from common attacks.",
                "technical": "Configure HSTS, CSP, X-Frame-Options, and X-Content-Type-Options headers on your web server.",
            },
            "Information Disclosure": {
                "simple": "Your server is revealing its software version, helping attackers find known weaknesses.",
                "technical": "Disable server version tokens (ServerTokens Prod / server_tokens off). Remove X-Powered-By header.",
            },
            "Cryptographic Failure": {
                "simple": "Your website uses unencrypted HTTP — attackers can intercept passwords and data.",
                "technical": "Obtain SSL/TLS certificate. Configure 301 redirects from HTTP to HTTPS. Enable HSTS.",
            },
        }

        finding["severity"] = severity_map.get(vuln_type, "Medium")

        rem = remediation_map.get(vuln_type, {})
        finding["remediation"] = rem.get("technical", "Investigate and apply targeted fixes.")
        finding["remediation_simple"] = rem.get("simple", "A security issue was detected.")
        finding["remediation_technical"] = rem.get("technical", "Investigate and apply targeted fixes.")

        # Build human-readable evidence string
        evidence_obj = finding.get("evidence", {})
        evidence_parts = []
        if evidence_obj.get("payload"):
            evidence_parts.append(f"Payload: {evidence_obj['payload']}")
        if evidence_obj.get("signatures_matched"):
            evidence_parts.append(f"Signatures: {', '.join(evidence_obj['signatures_matched'])}")
        if evidence_obj.get("missing_headers"):
            evidence_parts.append(f"Missing headers: {', '.join(evidence_obj['missing_headers'])}")
        if evidence_obj.get("detail"):
            evidence_parts.append(evidence_obj["detail"])
        finding["evidence_text"] = " | ".join(evidence_parts) if evidence_parts else str(evidence_obj)

        return finding

   

    def _attach_gemini_explanations(self, confirmed: list):
        """Call Gemini only for *confirmed* findings."""
        if not self.explainer.enabled:
            logger.info("Gemini Explainer not available — skipping explanations.")
            return

        for finding in confirmed:
            try:
                explanation = self.explainer.explain(
                    vuln_type=finding["type"],
                    url=finding.get("affected_url", self.target_url),
                    severity=finding.get("severity", "High"),
                    evidence=finding.get("evidence_text", ""),
                )
                finding["explanation"] = explanation
            except Exception as exc:
                logger.warning(f"Gemini explanation failed for {finding['type']}: {exc}")
                finding["explanation"] = self.explainer.fallback_explanation(finding["type"])
