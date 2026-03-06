"""
AI Explainer — Armora v2 (Layer 2).

Called ONLY for Confirmed findings.
Generates:
    1. Executive summary
    2. Technical explanation
    3. Stack-specific remediation

Uses OpenAI API (GPT-4o-mini by default).
If no confirmed vulnerabilities are found, this module is never invoked.
No ML. No anomaly scoring.
"""

import os
import json
import logging

logger = logging.getLogger(__name__)


class GeminiExplainer:
    """
    Uses AI (Gemini/GPT via OpenRouter) to generate contextual explanations
    for **Confirmed** vulnerability findings.
    """

    def __init__(self):
        from django.conf import settings
        self.api_key = getattr(settings, "OPENROUTER_API_KEY", "")
        self.enabled = False
        self.client = None
        self.model = getattr(settings, "OPENROUTER_MODEL", "google/gemini-2.0-flash-001")

        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://openrouter.ai/api/v1",
                )
                self.enabled = True
                logger.info(f"AI Explainer initialised with OpenRouter ({self.model}).")
            except Exception as exc:
                logger.warning(f"OpenRouter init failed: {exc}. Explanations will use fallbacks.")
        else:
            logger.info("OPENROUTER_API_KEY not set — AI explanations disabled.")

    def explain(self, vuln_type: str, url: str, severity: str, evidence: str) -> dict:
        """
        Generate a structured explanation for a Confirmed finding.
        """
        if not self.enabled:
            return self.fallback_explanation(vuln_type)

        # 1. Truncate evidence to save tokens (limit to ~4k chars)
        safe_evidence = (evidence[:4000] + "..[truncated]") if len(evidence) > 4000 else evidence

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a helpful senior security engineer. Your goal is to explain vulnerabilities in a way that ANYONE can understand, while maintaining professional high quality.\n"
                            "Rules:\n"
                            "1. Use simple, non-jargon language for the Executive Summary.\n"
                            "2. Be extremely precise and 'on-point'—avoid fluff.\n"
                            "3. Keep descriptions high-quality and actionable.\n"
                            "4. Output JSON format exactly as follows:\n"
                            "{\n"
                            "  \"executive_summary\": \"Precise 2-sentence non-technical risk summary using simple language\",\n"
                            "  \"technical_explanation\": \"Direct and technical but clear explanation of mechanics\",\n"
                            "  \"remediation\": \"Actionable steps with simple code examples if applicable\"\n"
                            "}"
                        )
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this confirmed finding:\nType: {vuln_type}\nURL: {url}\nSeverity: {severity}\nEvidence: {safe_evidence}"
                    },
                ],
                temperature=0.2,
                max_tokens=1000,
            )
            
            content = response.choices[0].message.content.strip()
            return self._parse_json_response(content, vuln_type)

        except Exception as exc:
            logger.warning(f"AI Explainer API failed: {exc}. Using fallback.")

        return self.fallback_explanation(vuln_type)

    def _parse_json_response(self, text: str, vuln_type: str) -> dict:
        """Parse JSON response with fallback to regex if model hallucinates non-JSON."""
        try:
            data = json.loads(text)
            return {
                "executive_summary": data.get("executive_summary", ""),
                "technical_explanation": data.get("technical_explanation", ""),
                "remediation": data.get("remediation", ""),
            }
        except Exception:
            # Emergency fallback: if it's not JSON, it might be raw text
            return self.fallback_explanation(vuln_type)

    # ------------------------------------------------------------------ #
    #  Fallback (no API key)                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def fallback_explanation(vuln_type: str) -> dict:
        """Generic explanation when OpenAI is unavailable."""
        fallbacks = {
            "SQL Injection": {
                "executive_summary": "A SQL Injection vulnerability was confirmed. Attackers can manipulate database queries to access, modify, or delete data.",
                "technical_explanation": "The application constructs SQL queries using unsanitised user input. The injected payload triggered a database error or returned data that confirms the parameter is injectable.",
                "remediation": "Use parameterized queries or an ORM. Apply input validation. Use least-privilege database accounts.",
            },
            "Cross-Site Scripting (XSS)": {
                "executive_summary": "A Cross-Site Scripting vulnerability was confirmed. Attackers can inject malicious scripts that execute in users' browsers.",
                "technical_explanation": "User-supplied input is reflected in the response without proper encoding. The injected payload was found verbatim in the HTML response.",
                "remediation": "Output-encode all user input contextually (HTML, JS, URL). Implement Content-Security-Policy headers.",
            },
            "Server-Side Request Forgery (SSRF)": {
                "executive_summary": "An SSRF vulnerability was confirmed. Attackers can make the server send requests to internal systems.",
                "technical_explanation": "The application processes user-supplied URLs without validation, allowing access to internal network resources or cloud metadata services.",
                "remediation": "Whitelist allowed domains. Block private IP ranges. Validate and sanitise all URL inputs server-side.",
            },
            "Local File Inclusion (LFI)": {
                "executive_summary": "A Local File Inclusion vulnerability was confirmed. Attackers can read sensitive server files.",
                "technical_explanation": "The application uses user-supplied input in file-path operations without proper sanitisation. Path-traversal payloads successfully retrieved system files.",
                "remediation": "Never use user input in file paths. Use a whitelist of allowed files. Chroot the application if possible.",
            },
            "Remote Code Execution (RCE)": {
                "executive_summary": "A Remote Code Execution vulnerability was confirmed. Attackers can execute arbitrary commands on the server.",
                "technical_explanation": "User input is passed to OS command execution functions. Injected command separators triggered observable output or timing differences.",
                "remediation": "Avoid passing user input to shell commands. Use language-native libraries. Apply strict input validation.",
            },
        }

        return fallbacks.get(vuln_type, {
            "executive_summary": f"A {vuln_type} vulnerability was confirmed through active verification.",
            "technical_explanation": "The exploit payload produced a detectable behaviour difference compared to the baseline request.",
            "remediation": "Investigate the affected endpoint and apply targeted security controls.",
        })
