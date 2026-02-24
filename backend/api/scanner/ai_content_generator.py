import json
import logging
from django.conf import settings
from openai import OpenAI

logger = logging.getLogger(__name__)

def generate_structured_intelligence(scan_data: dict) -> dict:
    """
    Call LLM to generate structured security intelligence in JSON format.
    """
    api_key = getattr(settings, "OPENROUTER_API_KEY", "")
    model = getattr(settings, "OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
    
    if not api_key:
        logger.error("OPENROUTER_API_KEY not set.")
        return _get_fallback_content(scan_data)

    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
    )

    prompt = _build_structured_prompt(scan_data)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a senior security architect. Return ONLY valid JSON. No backticks, no markdown, no commentary."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            timeout=120,
        )
        
        content = response.choices[0].message.content.strip()
        
        # Clean potential markdown wrappers
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        
        return json.loads(content.strip())
    except Exception as e:
        logger.exception(f"Structured AI generation failed: {e}")
        return _get_fallback_content(scan_data)

def _build_structured_prompt(scan_data: dict) -> str:
    findings_text = ""
    for idx, f in enumerate(scan_data.get('findings', [])):
        findings_text += f"\nFinding {idx+1}: {f['v_type']} ({f['severity']}) at {f['affected_url']}\nDescription: {f['explanation_technical']}\n"

    return f"""
Analyze the following security scan findings for {scan_data['target_url']}:
{findings_text}

Generate a structured security report in JSON format following this schema exactly:
{{
  "executive_summary": "High-level summary for non-technical stakeholders",
  "overall_risk_analysis": "Summary of total security posture",
  "vulnerabilities": [
    {{
      "title": "Specific name of the vulnerability",
      "technical_explanation": "Technical details of how it works",
      "risk_analysis": "Technical risk and exploitability",
      "business_impact": "Explain financial, operational, reputational, and compliance impact. Must be understandable by C-level executives (CEO/CFO). Avoid exaggeration.",
      "remediation": "Technical and strategic fix instructions"
    }}
  ]
}}

Return ONLY valid JSON.
"""

def _get_fallback_content(scan_data: dict) -> dict:
    return {
        "executive_summary": "Manual review required. System failed to generate AI summary.",
        "overall_risk_analysis": "Security posture evaluation pending.",
        "vulnerabilities": [
            {
                "title": f["v_type"],
                "technical_explanation": f["explanation_technical"],
                "risk_analysis": "High exploitability in current environment.",
                "business_impact": "Potential data loss and operational disruption.",
                "remediation": f["remediation_technical"]
            } for f in scan_data.get('findings', [])
        ]
    }
