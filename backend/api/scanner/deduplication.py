"""
Vulnerability Deduplication & Endpoint Tracking System.

This module provides post-processing deduplication for vulnerability findings.
It groups duplicate vulnerabilities by root cause while preserving all evidence
and tracking affected endpoints.

Philosophy:
- Detection ≠ Presentation
- One vulnerability can affect many endpoints
- Deduplication is a reporting improvement, not a detection change
- Never lose raw evidence
"""

import logging
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


# =============================================================================
# OWASP Category Mapping
# =============================================================================

OWASP_MAPPING = {
    'SQL Injection': 'A03:2021-Injection',
    'XSS': 'A03:2021-Injection',
    'Cross-Site Scripting': 'A03:2021-Injection',
    'Command Injection': 'A03:2021-Injection',
    'Path Traversal': 'A03:2021-Injection',
    'SSRF': 'A10:2021-SSRF',
    'Security Misconfiguration': 'A05:2021-Security-Misconfiguration',
    'Information Disclosure': 'A01:2021-Broken-Access-Control',
    'Cryptographic Failure': 'A02:2021-Cryptographic-Failures',
    'Broken Access Control': 'A01:2021-Broken-Access-Control',
    'AI-Detected Anomaly': 'A00:Unclassified',
}

# Root cause templates for common vulnerabilities
ROOT_CAUSE_TEMPLATES = {
    'SQL Injection': 'Unsanitized SQL parameter input',
    'XSS': 'Unsanitized user input reflected in HTML',
    'Cross-Site Scripting': 'Unsanitized user input reflected in HTML',
    'Command Injection': 'Unsanitized system command execution',
    'Path Traversal': 'Unsanitized file path input',
    'SSRF': 'Unsanitized URL input for server requests',
    'Security Misconfiguration': 'Missing security headers',
    'Information Disclosure': 'Exposed server/version information',
    'Cryptographic Failure': 'Unencrypted HTTP connection',
}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class EndpointEvidence:
    """Evidence from a specific affected endpoint."""
    endpoint: str           # e.g., "/product.php?id"
    full_url: str           # e.g., "http://example.com/product.php?id=1"
    parameter: str          # e.g., "id"
    payload: str            # e.g., "' OR 1=1 --"
    response_snippet: str   # e.g., "SQL syntax error"
    confidence: float       # Finding confidence
    detection_method: str   # 'rule' or 'ai'
    
    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'full_url': self.full_url,
            'parameter': self.parameter,
            'payload': self.payload,
            'response': self.response_snippet,
            'confidence': self.confidence,
            'detection_method': self.detection_method,
        }


@dataclass
class DeduplicatedVulnerability:
    """A deduplicated vulnerability with all affected endpoints grouped."""
    vulnerability_type: str
    severity: str
    owasp_category: str
    root_cause: str
    detection_method: str   # 'rule', 'ai', or 'hybrid' if both
    
    # Aggregated metrics
    occurrences: int = 0
    max_confidence: float = 0.0
    max_risk: int = 0
    
    # Affected endpoints list
    affected_endpoints: List[str] = field(default_factory=list)
    
    # Full evidence for each endpoint (preserved for forensics)
    evidence_list: List[EndpointEvidence] = field(default_factory=list)
    
    # Remediation (use the best one found)
    remediation: str = ""
    remediation_simple: str = ""
    remediation_technical: str = ""
    
    def add_evidence(self, evidence: EndpointEvidence):
        """Add evidence from an affected endpoint."""
        self.evidence_list.append(evidence)
        if evidence.endpoint not in self.affected_endpoints:
            self.affected_endpoints.append(evidence.endpoint)
        self.occurrences = len(self.affected_endpoints)
        self.max_confidence = max(self.max_confidence, evidence.confidence)
    
    def to_dict(self) -> Dict:
        return {
            'type': self.vulnerability_type,
            'severity': self.severity,
            'owasp': self.owasp_category,
            'root_cause': self.root_cause,
            'detection_method': self.detection_method,
            'occurrences': self.occurrences,
            'confidence': self.max_confidence,
            'risk': self.max_risk,
            'affected_endpoints': self.affected_endpoints,
            'evidence': [e.to_dict() for e in self.evidence_list[:10]],  # Limit for readability
            'remediation': self.remediation,
            'remediation_simple': self.remediation_simple,
            'remediation_technical': self.remediation_technical,
        }


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""
    total_endpoints_scanned: int = 0
    total_raw_findings: int = 0
    total_unique_vulnerabilities: int = 0
    affected_endpoints_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'total_endpoints_scanned': self.total_endpoints_scanned,
            'total_raw_findings': self.total_raw_findings,
            'total_unique_vulnerabilities': self.total_unique_vulnerabilities,
            'affected_endpoints_count': self.affected_endpoints_count,
        }


# =============================================================================
# Deduplication Engine
# =============================================================================

class DeduplicationEngine:
    """
    Post-processing engine to deduplicate vulnerability findings.
    
    Deduplication key is composed of:
    - Vulnerability type (e.g., SQL Injection)
    - OWASP category
    - Detection method (rule-based or AI)
    - Root cause (e.g., unsanitized input)
    
    Does NOT deduplicate:
    - Different vulnerability types
    - AI-only findings when rule-based confirmed exists
    - Same vuln across different auth contexts (future feature)
    """
    
    def __init__(self):
        self.raw_findings: List[Dict] = []
        self.deduplicated: Dict[str, DeduplicatedVulnerability] = {}
        self.scanned_endpoints: set = set()
        
    def _get_owasp_category(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP category."""
        return OWASP_MAPPING.get(vuln_type, 'A00:Unclassified')
    
    def _get_root_cause(self, vuln_type: str, evidence: str = "") -> str:
        """Determine root cause based on vulnerability type and evidence."""
        # Use template or derive from evidence
        return ROOT_CAUSE_TEMPLATES.get(vuln_type, f"Potential {vuln_type} vulnerability")
    
    def _extract_endpoint(self, url: str) -> str:
        """
        Extract normalized endpoint from URL for grouping.
        
        Examples:
        - "http://example.com/product.php?id=1" -> "/product.php?id"
        - "http://example.com/search.php?q=test" -> "/search.php?q"
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        
        # Get parameter names (not values) for grouping
        if parsed.query:
            params = parse_qs(parsed.query)
            param_names = sorted(params.keys())
            if param_names:
                return f"{path}?{','.join(param_names)}"
        
        return path
    
    def _extract_parameter(self, url: str) -> str:
        """Extract the parameter name from URL if present."""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            return ', '.join(sorted(params.keys()))
        return ""
    
    def _generate_dedup_key(
        self,
        vuln_type: str,
        owasp: str,
        detection_method: str,
        root_cause: str
    ) -> str:
        """
        Generate a deduplication key for grouping vulnerabilities.
        
        Key format: TYPE|OWASP|METHOD|ROOT_CAUSE_HASH
        """
        # Hash root cause for consistent key length
        root_hash = hashlib.md5(root_cause.encode()).hexdigest()[:8]
        return f"{vuln_type}|{owasp}|{detection_method}|{root_hash}"
    
    def process_findings(
        self,
        raw_findings: List[Dict],
        scanned_urls: List[str]
    ) -> Dict[str, Any]:
        """
        Process raw findings and return deduplicated results.
        
        Args:
            raw_findings: List of raw finding dictionaries from scanner
            scanned_urls: List of all URLs that were scanned
            
        Returns:
            Dictionary with scan_summary and deduplicated vulnerabilities
        """
        self.raw_findings = raw_findings
        self.deduplicated = {}
        self.scanned_endpoints = set()
        
        # Track all scanned endpoints
        for url in scanned_urls:
            endpoint = self._extract_endpoint(url)
            self.scanned_endpoints.add(endpoint)
        
        # Process each raw finding
        for finding in raw_findings:
            self._process_single_finding(finding)
        
        # Build and return result
        return self._build_result()
    
    def _process_single_finding(self, finding: Dict):
        """Process a single finding and add to deduplication groups."""
        # Extract required fields with defaults
        vuln_type = finding.get('type', 'Unknown')
        url = finding.get('affected_url', '')
        severity = finding.get('severity', 'Medium')
        evidence = finding.get('evidence', '')
        detection_method = finding.get('detection_method', 'rule')
        confidence = finding.get('total_confidence', finding.get('confidence', 50))
        risk_score = finding.get('risk_score', 50)
        
        # Get remediation fields
        remediation = finding.get('remediation', '')
        remediation_simple = finding.get('remediation_simple', '')
        remediation_technical = finding.get('remediation_technical', '')
        
        # Derive deduplication components
        owasp = self._get_owasp_category(vuln_type)
        root_cause = self._get_root_cause(vuln_type, evidence)
        endpoint = self._extract_endpoint(url)
        parameter = self._extract_parameter(url)
        
        # Generate deduplication key
        dedup_key = self._generate_dedup_key(vuln_type, owasp, detection_method, root_cause)
        
        # Create evidence record
        evidence_record = EndpointEvidence(
            endpoint=endpoint,
            full_url=url,
            parameter=parameter,
            payload=self._extract_payload(evidence),
            response_snippet=self._extract_response(evidence),
            confidence=confidence,
            detection_method=detection_method,
        )
        
        # Add to existing group or create new one
        if dedup_key in self.deduplicated:
            self.deduplicated[dedup_key].add_evidence(evidence_record)
            # Update max values
            self.deduplicated[dedup_key].max_risk = max(
                self.deduplicated[dedup_key].max_risk, 
                risk_score
            )
        else:
            # Create new deduplicated vulnerability
            dedup_vuln = DeduplicatedVulnerability(
                vulnerability_type=vuln_type,
                severity=severity,
                owasp_category=owasp,
                root_cause=root_cause,
                detection_method=detection_method,
                max_risk=risk_score,
                remediation=remediation,
                remediation_simple=remediation_simple,
                remediation_technical=remediation_technical,
            )
            dedup_vuln.add_evidence(evidence_record)
            self.deduplicated[dedup_key] = dedup_vuln
    
    def _extract_payload(self, evidence: str) -> str:
        """Extract payload from evidence string if present."""
        # Try to extract payload patterns
        if "payload:" in evidence.lower():
            parts = evidence.lower().split("payload:")
            if len(parts) > 1:
                return parts[1].strip()[:100]
        return evidence[:100] if evidence else ""
    
    def _extract_response(self, evidence: str) -> str:
        """Extract response snippet from evidence."""
        # Truncate for storage
        return evidence[:200] if evidence else ""
    
    def _build_result(self) -> Dict[str, Any]:
        """Build the final deduplicated result structure."""
        # Calculate affected endpoints count
        all_affected = set()
        for vuln in self.deduplicated.values():
            all_affected.update(vuln.affected_endpoints)
        
        # Build summary
        summary = ScanSummary(
            total_endpoints_scanned=len(self.scanned_endpoints),
            total_raw_findings=len(self.raw_findings),
            total_unique_vulnerabilities=len(self.deduplicated),
            affected_endpoints_count=len(all_affected),
        )
        
        # Sort vulnerabilities by severity then occurrences
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_vulns = sorted(
            self.deduplicated.values(),
            key=lambda v: (severity_order.get(v.severity, 5), -v.occurrences)
        )
        
        return {
            'scan_summary': summary.to_dict(),
            'vulnerabilities': [v.to_dict() for v in sorted_vulns],
            # Preserve raw findings for forensic purposes
            'raw_findings': self.raw_findings,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the deduplication process."""
        if not self.raw_findings:
            return {'message': 'No findings processed'}
        
        reduction = 0
        if len(self.raw_findings) > 0:
            reduction = (1 - len(self.deduplicated) / len(self.raw_findings)) * 100
        
        return {
            'raw_findings_count': len(self.raw_findings),
            'deduplicated_count': len(self.deduplicated),
            'reduction_percentage': round(reduction, 1),
            'endpoints_scanned': len(self.scanned_endpoints),
        }


# =============================================================================
# Helper Functions
# =============================================================================

def deduplicate_findings(
    raw_findings: List[Dict],
    scanned_urls: List[str]
) -> Dict[str, Any]:
    """
    Convenience function to deduplicate findings.
    
    Args:
        raw_findings: List of raw finding dictionaries from scanner
        scanned_urls: List of all URLs that were scanned
        
    Returns:
        Dictionary with scan_summary and deduplicated vulnerabilities
        
    Example:
        >>> findings = scanner.run_scans(crawled_data)
        >>> result = deduplicate_findings(findings, crawled_data['visited_urls'])
        >>> print(result['scan_summary'])
    """
    engine = DeduplicationEngine()
    return engine.process_findings(raw_findings, scanned_urls)


def format_report(deduplicated_result: Dict[str, Any]) -> str:
    """
    Format deduplicated results as a readable text report.
    
    Args:
        deduplicated_result: Output from deduplicate_findings()
        
    Returns:
        Formatted string report
    """
    summary = deduplicated_result['scan_summary']
    vulns = deduplicated_result['vulnerabilities']
    
    lines = [
        "=" * 60,
        "VULNERABILITY SCAN REPORT (DEDUPLICATED)",
        "=" * 60,
        "",
        "SCAN SUMMARY",
        "-" * 40,
        f"Total endpoints scanned: {summary['total_endpoints_scanned']}",
        f"Total raw findings: {summary['total_raw_findings']}",
        f"Unique vulnerabilities: {summary['total_unique_vulnerabilities']}",
        f"Affected endpoints: {summary['affected_endpoints_count']}",
        "",
        "VULNERABILITIES",
        "-" * 40,
    ]
    
    for i, vuln in enumerate(vulns, 1):
        lines.append(f"\n[{i}] {vuln['type']} ({vuln['severity']})")
        lines.append(f"    OWASP: {vuln['owasp']}")
        lines.append(f"    Root Cause: {vuln['root_cause']}")
        lines.append(f"    Occurrences: {vuln['occurrences']} endpoints")
        lines.append(f"    Confidence: {vuln['confidence']}%")
        lines.append(f"    Affected: {', '.join(vuln['affected_endpoints'][:5])}")
        if len(vuln['affected_endpoints']) > 5:
            lines.append(f"             ... and {len(vuln['affected_endpoints']) - 5} more")
    
    lines.append("")
    lines.append("=" * 60)
    
    return "\n".join(lines)
