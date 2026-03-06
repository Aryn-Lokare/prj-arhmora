import json
import logging
from django.conf import settings

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

    try:
        from openai import OpenAI
    except ImportError:
        logger.error("openai package not installed.")
        return _get_fallback_content(scan_data)

    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
    )

    prompt = _build_structured_prompt(scan_data)

    try:
        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system", 
                    "content": (
                        "You are a helpful senior security architect. Your goal is to generate a premium security report summary that is high-quality, precise, and written in simple language understandable to non-experts.\n"
                        "Rules:\n"
                        "1. Avoid jargon in the Executive Summary.\n"
                        "2. Be concise and 'on-point'.\n"
                        "3. Use a professional yet simple tone.\n"
                        "4. Output ONLY valid JSON."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2500,
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
Analyze the security scan findings for {scan_data['target_url']}:
{findings_text}

Generate a premium security intelligence report in JSON format.
Requirements for Content:
1. EXECUTIVE SUMMARY: Use simple language understandable by a CEO or non-technical business owner. Explain the risk precise and accurately.
2. QUALITY: Descriptions must be professional and high-quality, avoiding 'detectory' jargon.
3. PRECISION: Be direct. Use short, punchy sentences.
4. TONE: Professional yet accessible.

JSON Schema:
{{
  "executive_summary": "Simple 2-3 sentence summary for non-experts",
  "overall_risk_analysis": "Precise evaluation of the security posture",
  "vulnerabilities": [
    {{
      "title": "Clear name of vulnerability",
      "technical_explanation": "Direct explanation of the mechanics",
      "risk_analysis": "What is the actual danger?",
      "business_impact": "Explain financial and operational risk in simple terms for stakeholders",
      "remediation": "Clear, actionable fix instructions"
    }}
  ]
}}
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
