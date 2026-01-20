"""
Fix Prioritization Engine.

This module ranks detected vulnerabilities for remediation priority based on:
- Severity
- AI confidence
- Endpoint sensitivity
- Estimated fix effort
"""

from typing import Dict, List, Optional


class FixPrioritizer:
    """
    Rank vulnerabilities for remediation priority.
    
    Priority is calculated using a weighted formula that considers:
    - Severity (High=3, Medium=2, Low=1)
    - AI confidence score (0.0-1.0)
    - Endpoint sensitivity (admin=1.0, auth=0.9, data=0.8, api=0.6, public=0.2)
    - Estimated fix effort (1=easy, 2=medium, 3=hard)
    """
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Info': 0,
    }
    
    # Endpoint sensitivity scores
    ENDPOINT_SENSITIVITY = {
        'admin': 1.0,
        'auth': 0.9,
        'data': 0.8,
        'api': 0.6,
        'public': 0.2,
    }
    
    # Estimated fix effort (1=easy, 2=medium, 3=hard)
    EFFORT_ESTIMATES = {
        'Security Misconfiguration': 1,
        'Information Disclosure': 1,
        'Missing Headers': 1,
        'Cryptographic Failure': 2,
        'Reflected XSS': 2,
        'XSS': 2,
        'SSRF Risk': 2,
        'SQL Injection': 3,
        'AI-Detected Anomaly': 2,
    }
    
    # Default effort for unknown vulnerability types
    DEFAULT_EFFORT = 2
    
    def __init__(self):
        """Initialize the fix prioritizer."""
        pass
    
    def _get_severity_weight(self, severity: str) -> int:
        """Get numerical weight for severity level."""
        return self.SEVERITY_WEIGHTS.get(severity, 0)
    
    def _get_endpoint_sensitivity(self, endpoint_type: str) -> float:
        """Get sensitivity score for endpoint type."""
        return self.ENDPOINT_SENSITIVITY.get(endpoint_type, 0.2)
    
    def _get_fix_effort(self, v_type: str) -> int:
        """Get estimated fix effort for vulnerability type."""
        return self.EFFORT_ESTIMATES.get(v_type, self.DEFAULT_EFFORT)
    
    def calculate_priority_score(self, finding: Dict) -> float:
        """
        Calculate priority score for a single finding.
        
        Priority Formula:
        priority = (severity_weight * 3) + (confidence * 2) + (sensitivity * 2) - (effort * 0.5)
        
        Higher score = higher priority for remediation.
        
        Args:
            finding: Dictionary containing finding details with keys:
                - severity: 'High', 'Medium', 'Low', or 'Info'
                - confidence: float 0.0-1.0 (optional, defaults to 0.5)
                - endpoint_sensitivity: str (optional, defaults to 'public')
                - type: vulnerability type string
                
        Returns:
            Priority score (higher = more urgent)
        """
        severity = finding.get('severity', 'Low')
        confidence = finding.get('confidence', 0.5)
        endpoint_type = finding.get('endpoint_sensitivity', 'public')
        v_type = finding.get('type', '')
        
        severity_weight = self._get_severity_weight(severity)
        sensitivity = self._get_endpoint_sensitivity(endpoint_type)
        effort = self._get_fix_effort(v_type)
        
        # Priority formula
        priority = (
            (severity_weight * 3.0) +
            (confidence * 2.0) +
            (sensitivity * 2.0) -
            (effort * 0.5)
        )
        
        return priority
    
    def rank_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Rank findings by remediation priority.
        
        Returns findings sorted by priority (highest first) with
        priority_rank field added (1 = highest priority).
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of findings sorted by priority with priority_rank added
        """
        if not findings:
            return []
        
        # Calculate priority scores
        scored_findings = []
        for finding in findings:
            finding_copy = finding.copy()
            finding_copy['_priority_score'] = self.calculate_priority_score(finding)
            scored_findings.append(finding_copy)
        
        # Sort by priority score (descending)
        scored_findings.sort(key=lambda f: f['_priority_score'], reverse=True)
        
        # Add priority rank and remove internal score
        for rank, finding in enumerate(scored_findings, 1):
            finding['priority_rank'] = rank
            del finding['_priority_score']
        
        return scored_findings
    
    def get_priority_summary(self, findings: List[Dict]) -> Dict:
        """
        Get a summary of findings by priority level.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Summary dictionary with counts by severity and priority tier
        """
        ranked = self.rank_findings(findings)
        
        high_priority = [f for f in ranked if f.get('priority_rank', 999) <= 3]
        medium_priority = [f for f in ranked if 3 < f.get('priority_rank', 999) <= 10]
        low_priority = [f for f in ranked if f.get('priority_rank', 999) > 10]
        
        severity_counts = {
            'High': sum(1 for f in findings if f.get('severity') == 'High'),
            'Medium': sum(1 for f in findings if f.get('severity') == 'Medium'),
            'Low': sum(1 for f in findings if f.get('severity') == 'Low'),
            'Info': sum(1 for f in findings if f.get('severity') == 'Info'),
        }
        
        return {
            'total_findings': len(findings),
            'high_priority_count': len(high_priority),
            'medium_priority_count': len(medium_priority),
            'low_priority_count': len(low_priority),
            'severity_counts': severity_counts,
            'top_3_findings': ranked[:3] if ranked else [],
        }
