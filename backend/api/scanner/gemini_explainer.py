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
        self.enabled = False
        self.client = None

        # Priority 1: Direct OpenAI API key
        openai_key = getattr(settings, "OPENAI_API_KEY", "")
        # Priority 2: OpenRouter API key (legacy)
        openrouter_key = getattr(settings, "OPENROUTER_API_KEY", "")

        if openai_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=openai_key)
                self.model = getattr(settings, "OPENAI_MODEL", "gpt-4o-mini")
                self.enabled = True
                logger.info(f"AI Explainer initialised with OpenAI ({self.model}).")
            except Exception as exc:
                logger.warning(f"OpenAI init failed: {exc}. Explanations will use fallbacks.")
        elif openrouter_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=openrouter_key,
                    base_url="https://openrouter.ai/api/v1",
                )
                self.model = getattr(settings, "OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
                self.enabled = True
                logger.info(f"AI Explainer initialised with OpenRouter ({self.model}).")
            except Exception as exc:
                logger.warning(f"OpenRouter init failed: {exc}. Explanations will use fallbacks.")
        else:
            logger.info("No AI API key set — AI explanations disabled.")

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
                            "You are a helpful senior security engineer. Your goal is to explain vulnerabilities concisely while providing technical remediation.\n"
                            "Rules:\n"
                            "1. Use simple language for the Executive Summary.\n"
                            "2. Be extremely concise. Use the MINIMUM number of tokens required. Avoid fluff.\n"
                            "3. For the 'remediation' field, always include a brief Markdown code snippet illustrating the fix.\n"
                            "4. Output JSON format exactly as follows:\n"
                            "{\n"
                            "  \"executive_summary\": \"Precise 2-sentence summary\",\n"
                            "  \"technical_explanation\": \"Direct explanation of mechanics\",\n"
                            "  \"remediation\": \"Actionable steps + Markdown code snippet\"\n"
                            "}"
                        )
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this finding:\nType: {vuln_type}\nURL: {url}\nSeverity: {severity}\nEvidence: {safe_evidence}"
                    },
                ],
                temperature=0.1,
                max_tokens=600,
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
                "executive_summary": "A SQL Injection vulnerability was confirmed. Attackers can manipulate database queries to access or modify sensitive data.",
                "technical_explanation": "The application constructs SQL queries using unsanitised user input. The injected payload triggered a database response confirming the parameter is injectable.",
                "remediation": "Use parameterized queries or an ORM. \n\n```python\n# Safe (Django ORM)\nUser.objects.filter(username=username)\n\n# Safe (Raw SQL)\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", [user_id])\n```",
            },
            "Cross-Site Scripting (XSS)": {
                "executive_summary": "A Cross-Site Scripting vulnerability was confirmed. Attackers can inject malicious scripts that execute in users' browsers.",
                "technical_explanation": "User-supplied input is reflected in the response without proper encoding. The injected payload was captured verbatim in the HTML response.",
                "remediation": "Contextually encode all user-supplied data before rendering it in the UI.\n\n```javascript\n// Safe approach (React automatically escapes)\n<div>{userInput}</div>\n\n// Safe approach (Manual escaping)\nconst escaped = text.replace(/</g, '&lt;').replace(/>/g, '&gt;');\n```",
            },
            "Server-Side Request Forgery (SSRF)": {
                "executive_summary": "An SSRF vulnerability was confirmed. Attackers can force the server to send requests to internal systems.",
                "technical_explanation": "The application processes user-supplied URLs without validation, allowing access to internal network resources or metadata services.",
                "remediation": "Whitelist allowed domains and block private IP ranges.\n\n```python\ndef is_safe_url(url):\n    allowed_domains = [\"api.trusted.com\"]\n    parsed = urlparse(url)\n    return parsed.netloc in allowed_domains\n```",
            },
            "Local File Inclusion (LFI)": {
                "executive_summary": "An LFI vulnerability was confirmed. Attackers can read sensitive server files like /etc/passwd.",
                "technical_explanation": "The application uses user-supplied input in file operations without sanitisation, allowing directory traversal (../../).",
                "remediation": "Never use user input directly in file paths. Use a strict whitelist of allowed filenames.\n\n```python\n# Safe approach\nALLOWED_FILES = {'image1.jpg', 'image2.jpg'}\nif filename in ALLOWED_FILES:\n    with open(f'uploads/{filename}', 'rb') as f: ...\n```",
            },
            "Remote Code Execution (RCE)": {
                "executive_summary": "A Remote Code Execution vulnerability was confirmed. Attackers can execute arbitrary OS commands on your server.",
                "technical_explanation": "User input is passed to shell execution functions. The injected command produced observable differences in the response.",
                "remediation": "Avoid shell execution. Use language-native APIs instead.\n\n```python\n# UNSAFE\nos.system(f\"ping {host}\")\n\n# SAFE\nimport subprocess\nsubprocess.run([\"ping\", \"-c\", \"1\", host], check=True)\n```",
            },
        }

        return fallbacks.get(vuln_type, {
            "executive_summary": f"A {vuln_type} vulnerability was confirmed through active verification.",
            "technical_explanation": "The exploit payload produced a detectable behaviour difference compared to the baseline request.",
            "remediation": "Investigate the affected endpoint and apply targeted security controls.",
        })
