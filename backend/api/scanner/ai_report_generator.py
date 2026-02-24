# backend/api/scanner/ai_report_generator.py

import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

def generate_html_report(scan_data: dict) -> str:
    """
    Call LLM (Gemini via OpenRouter) to generate a full HTML5 security report.
    Returns valid HTML5 string with inline CSS.
    """
    api_key = getattr(settings, "OPENROUTER_API_KEY", "")
    model = getattr(settings, "OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
    
    if not api_key:
        logger.error("OPENROUTER_API_KEY not set. Cannot generate AI report.")
        return "<html><body><h1>Error: AI Configuration Missing</h1></body></html>"

    try:
        from openai import OpenAI
        client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )
    except ImportError:
        logger.error("openai-python not installed.")
        return "<html><body><h1>Error: LLM Client Missing</h1></body></html>"

    # Truncate findings if too long to avoid token limits or slow responses
    findings = scan_data.get('findings', [])
    if len(findings) > 30:
        scan_data['findings'] = findings[:30]

    prompt = _build_report_prompt(scan_data)
    print(f"DEBUG: Prompt constructed. Length: {len(prompt)} chars.", flush=True)

    try:
        print(f"DEBUG: Calling OpenRouter API with model {model}...", flush=True)
        import time
        start_time = time.time()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a senior security architect. Return ONLY valid, professional HTML5. No markdown, no backticks, no talk."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            timeout=120, # 2 minute timeout
        )
        duration = time.time() - start_time
        html_content = response.choices[0].message.content.strip()
        print(f"DEBUG: AI response received in {duration:.2f}s. Content length: {len(html_content)} chars.", flush=True)
        
        # Strip potential markdown code block wrappers
        if html_content.startswith("```html"):
            html_content = html_content[7:]
        if html_content.endswith("```"):
            html_content = html_content[:-3]
            
        return html_content.strip()
    except Exception as e:
        logger.exception(f"AI Report Generation failed: {e}")
        return f"<html><body><h1>Technical Error in Report Generation</h1><p>{str(e)}</p></body></html>"

def _build_report_prompt(scan_data: dict) -> str:
    findings_summary = ""
    for f in scan_data.get('findings', []):
        findings_summary += f"- Type: {f['v_type']}, Severity: {f['severity']}, URL: {f['affected_url']}\n"
        findings_summary += f"  Explanation: {f.get('explanation_technical', 'N/A')}\n"
        findings_summary += f"  Remediation: {f.get('remediation_technical', 'N/A')}\n\n"

    return f"""
Generate a high-end, executive-level security assessment report in HTML5 for ARMORA.

TARGET: {scan_data.get('target_url')}
SCAN TIMESTAMP: {scan_data.get('timestamp')}
TOTAL FINDINGS: {len(scan_data.get('findings', []))}

FINDINGS DATA:
{findings_summary}

STRICT REQUIREMENTS:
1. Return ONLY valid HTML5 code.
2. Use professional, modern typography (sans-serif).
3. Theme: Dark enterprise aesthetic (Background: #0a0a0b, Text: #f8fafc).
4. ALL CSS MUST BE INLINE.
5. NO JavaScript. NO external assets or fonts.
6. Sections needed: 
   - Cover Page with target URL and large ARMORA branding
   - Executive Summary (AI-generated based on findings)
   - Risk Overview Table
   - Detailed Vulnerability breakdown (one per page using CSS 'break-after: page')
   - Remediation Roadmap
   - Footer on every page with timestamp
7. Severity Badges: 
   - High: Background #ef4444, Text #ffffff
   - Medium: Background #f59e0b, Text #ffffff
   - Low: Background #10b981, Text #ffffff
8. Do not include markdown backticks or explaining text.
"""
