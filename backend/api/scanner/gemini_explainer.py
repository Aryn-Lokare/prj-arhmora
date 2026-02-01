"""
Gemini AI Explainer Module

Generates dynamic, context-aware explanations for vulnerability findings.
Provides two explanation types:
1. Non-Technical: Easy to understand for business users and non-developers
2. Technical: Detailed technical language for developers and security professionals
"""

import os
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)


class GeminiExplainer:
    """
    Uses Google Gemini API to generate contextual explanations for security findings.
    
    Features:
    - Dual explanation types (non-technical and technical)
    - Accurate, non-misleading language
    - Caching to reduce API calls
    - Graceful fallback on API errors
    """
    
    def __init__(self):
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.client = None
        self.enabled = False
        
        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
                self.enabled = True
                logger.info("GeminiExplainer initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
                self.enabled = False
        else:
            logger.warning("GEMINI_API_KEY not found. AI explanations disabled.")
    
    def generate_explanation(
        self,
        finding_type: str,
        url: str,
        severity: str,
        evidence: str,
        risk_score: int
    ) -> dict:
        """
        Generate both non-technical and technical explanations for a finding.
        
        Args:
            finding_type: Type of vulnerability (e.g., 'SQL Injection', 'XSS')
            url: The affected URL
            severity: Severity level ('High', 'Medium', 'Low', 'Info')
            evidence: Technical evidence of the finding
            risk_score: Risk score (0-100)
            
        Returns:
            dict: {
                'explanation_simple': str,  # For non-technical users
                'explanation_technical': str,  # For technical users
                'remediation_simple': str,  # Fix instructions for non-technical
                'remediation_technical': str  # Fix instructions for technical
            }
        """
        if not self.enabled:
            return self._get_fallback_explanation(finding_type, evidence)
        
        try:
            # Use cached version if available
            cache_key = f"{finding_type}:{severity}:{evidence[:100]}"
            return self._generate_cached(cache_key, finding_type, url, severity, evidence, risk_score)
        except Exception as e:
            logger.error(f"Gemini explanation error: {e}")
            return self._get_fallback_explanation(finding_type, evidence)
    
    @lru_cache(maxsize=100)
    def _generate_cached(
        self,
        cache_key: str,
        finding_type: str,
        url: str,
        severity: str,
        evidence: str,
        risk_score: int
    ) -> dict:
        """Cached version of explanation generation."""
        
        prompt = f"""You are a cybersecurity expert providing accurate vulnerability explanations.

VULNERABILITY DETAILS:
- Type: {finding_type}
- Severity: {severity}
- Risk Score: {risk_score}/100
- Evidence Found: {evidence}
- Affected URL: {url}

Generate explanations for this security finding. Be ACCURATE and DO NOT MISLEAD the user.
- If the finding is uncertain, clearly state it might be a false positive
- Do not exaggerate the risk or create unnecessary alarm
- Base your explanation strictly on the evidence provided

Provide your response in EXACTLY this format (use these exact headers):

NON_TECHNICAL_EXPLANATION:
[Write 2-3 sentences explaining what this vulnerability means in plain English. 
Avoid technical jargon. Explain what could happen if exploited, in terms a business owner would understand.
Be honest about the certainty level.]

TECHNICAL_EXPLANATION:
[Write 2-3 sentences with technical details about the vulnerability.
Include relevant technical terms, attack vectors, and potential impact.
Reference the specific evidence found.]

NON_TECHNICAL_REMEDIATION:
[Write 2-3 sentences explaining how to fix this in simple terms.
Focus on what needs to happen, not how to implement it technically.]

TECHNICAL_REMEDIATION:
[Write detailed technical fix instructions.
Include specific configurations, code changes, or security controls needed.
Reference industry best practices or standards where applicable.]
"""

        response = self.client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt
        )
        return self._parse_response(response.text)
    
    def _parse_response(self, response_text: str) -> dict:
        """Parse Gemini response into structured format."""
        result = {
            'explanation_simple': '',
            'explanation_technical': '',
            'remediation_simple': '',
            'remediation_technical': ''
        }
        
        sections = {
            'NON_TECHNICAL_EXPLANATION:': 'explanation_simple',
            'TECHNICAL_EXPLANATION:': 'explanation_technical',
            'NON_TECHNICAL_REMEDIATION:': 'remediation_simple',
            'TECHNICAL_REMEDIATION:': 'remediation_technical'
        }
        
        current_section = None
        current_content = []
        
        for line in response_text.split('\n'):
            line_stripped = line.strip()
            
            # Check if this line is a section header
            matched_section = None
            for header, key in sections.items():
                if line_stripped.startswith(header):
                    matched_section = key
                    break
            
            if matched_section:
                # Save previous section's content
                if current_section and current_content:
                    result[current_section] = ' '.join(current_content).strip()
                current_section = matched_section
                current_content = []
                # Check if content is on same line as header
                for header in sections:
                    if line_stripped.startswith(header):
                        remaining = line_stripped[len(header):].strip()
                        if remaining:
                            current_content.append(remaining)
                        break
            elif current_section and line_stripped:
                current_content.append(line_stripped)
        
        # Save the last section
        if current_section and current_content:
            result[current_section] = ' '.join(current_content).strip()
        
        return result
    
    def _get_fallback_explanation(self, finding_type: str, evidence: str) -> dict:
        """
        Fallback explanations when Gemini is unavailable.
        These are generic but accurate.
        """
        fallbacks = {
            'SQL Injection': {
                'explanation_simple': 'A potential database security issue was detected. This could allow unauthorized access to your data.',
                'explanation_technical': f'Possible SQL injection vulnerability detected. Evidence: {evidence}',
                'remediation_simple': 'Have your developer review how user input is processed before being sent to the database.',
                'remediation_technical': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.'
            },
            'Reflected XSS': {
                'explanation_simple': 'A potential script injection issue was found. This could allow attackers to run malicious code on your visitors\' browsers.',
                'explanation_technical': f'Potential Reflected Cross-Site Scripting (XSS) vulnerability. Evidence: {evidence}',
                'remediation_simple': 'Have your developer ensure all user input is properly cleaned before displaying on pages.',
                'remediation_technical': 'Implement context-appropriate output encoding. Use Content-Security-Policy headers. Sanitize all user input before rendering.'
            },
            'Security Misconfiguration': {
                'explanation_simple': 'Your server\'s security settings could be improved. Some recommended protections are not enabled.',
                'explanation_technical': f'Security headers missing or misconfigured. Evidence: {evidence}',
                'remediation_simple': 'Ask your hosting provider or developer to enable recommended security settings.',
                'remediation_technical': 'Configure security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options. Review server configuration against security benchmarks.'
            },
            'AI-Detected Anomaly': {
                'explanation_simple': 'Our AI detected unusual patterns that may indicate a security issue. Further investigation is recommended.',
                'explanation_technical': f'AI anomaly detection flagged this request. Evidence: {evidence}',
                'remediation_simple': 'Review the flagged URL patterns with your security team to determine if action is needed.',
                'remediation_technical': 'Analyze request logs for the flagged patterns. Implement WAF rules if attack patterns are confirmed. Consider rate limiting suspicious sources.'
            }
        }
        
        # Return specific fallback or generic one
        if finding_type in fallbacks:
            return fallbacks[finding_type]
        
        return {
            'explanation_simple': f'A potential security issue ({finding_type}) was detected that may need attention.',
            'explanation_technical': f'{finding_type} detected. Evidence: {evidence}',
            'remediation_simple': 'Consult with a security professional to review and address this finding.',
            'remediation_technical': f'Review and remediate the {finding_type} vulnerability following industry best practices.'
        }
