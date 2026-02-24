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
import re
import logging

logger = logging.getLogger(__name__)


class GeminiExplainer:
    """
    Uses OpenAI API to generate contextual explanations
    for **Confirmed** vulnerability findings.

    Class name kept as GeminiExplainer for backward compatibility
    with scanner.py imports.
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

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    def explain(self, vuln_type: str, url: str, severity: str, evidence: str) -> dict:
        """
        Generate a structured explanation for a Confirmed finding.

        Returns:
            {
                "executive_summary": str,
                "technical_explanation": str,
                "remediation": str,
            }
        """
        if not self.enabled:
            return self.fallback_explanation(vuln_type)

        prompt = self._build_prompt(vuln_type, url, severity, evidence)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior application-security engineer providing vulnerability analysis.",
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.3,
                max_tokens=1024,
            )
            text = response.choices[0].message.content.strip()
            if text:
                return self._parse_response(text)
        except Exception as exc:
            logger.warning(f"OpenAI API call failed: {exc}. Using fallback.")

        return self.fallback_explanation(vuln_type)

    # ------------------------------------------------------------------ #
    #  Prompt construction                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_prompt(vuln_type: str, url: str, severity: str, evidence: str) -> str:
        return (
            "A confirmed vulnerability has been verified through active exploit testing.\n\n"
            f"**Vulnerability:** {vuln_type}\n"
            f"**Affected URL:** {url}\n"
            f"**Severity:** {severity}\n"
            f"**Evidence:** {evidence}\n\n"
            "Provide your analysis in EXACTLY this format:\n\n"
            "## Executive Summary\n"
            "[2-3 sentence non-technical summary of the risk for business stakeholders]\n\n"
            "## Technical Explanation\n"
            "[Detailed technical explanation of how this vulnerability works, "
            "what the attacker can achieve, and why the evidence confirms exploitation]\n\n"
            "## Remediation\n"
            "[Specific, actionable remediation steps. Include code examples if appropriate. "
            "Reference the relevant tech stack.]\n"
        )

    # ------------------------------------------------------------------ #
    #  Response parsing                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_response(text: str) -> dict:
        """Parse OpenAI response into the three sections."""
        result = {
            "executive_summary": "",
            "technical_explanation": "",
            "remediation": "",
        }

        sections = re.split(r"##\s+", text)
        for section in sections:
            section_stripped = section.strip()
            lower = section_stripped.lower()

            if lower.startswith("executive summary"):
                result["executive_summary"] = section_stripped.split("\n", 1)[-1].strip()
            elif lower.startswith("technical explanation"):
                result["technical_explanation"] = section_stripped.split("\n", 1)[-1].strip()
            elif lower.startswith("remediation"):
                result["remediation"] = section_stripped.split("\n", 1)[-1].strip()

        # If parsing failed, use the full text as executive summary
        if not any(result.values()):
            result["executive_summary"] = text

        return result

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
