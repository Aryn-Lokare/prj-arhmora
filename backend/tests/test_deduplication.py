"""
Unit Tests for Vulnerability Deduplication System.

Tests the deduplication logic, endpoint tracking, and report formatting.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.scanner.deduplication import (
    DeduplicationEngine,
    deduplicate_findings,
    format_report,
    EndpointEvidence,
    DeduplicatedVulnerability,
)


class TestDeduplicationEngine:
    """Tests for the DeduplicationEngine class."""
    
    @pytest.fixture
    def engine(self):
        return DeduplicationEngine()
    
    @pytest.fixture
    def sample_findings(self):
        """Sample raw findings with duplicates."""
        return [
            {
                'type': 'SQL Injection',
                'affected_url': 'http://example.com/product.php?id=1',
                'severity': 'High',
                'evidence': "SQL syntax error near '1''",
                'detection_method': 'rule',
                'total_confidence': 75,
                'risk_score': 90,
                'remediation': 'Use prepared statements',
            },
            {
                'type': 'SQL Injection',
                'affected_url': 'http://example.com/list.php?cat=2',
                'severity': 'High',
                'evidence': "SQL syntax error near '2''",
                'detection_method': 'rule',
                'total_confidence': 80,
                'risk_score': 85,
                'remediation': 'Use prepared statements',
            },
            {
                'type': 'SQL Injection',
                'affected_url': 'http://example.com/search.php?q=test',
                'severity': 'High',
                'evidence': "MySQL error",
                'detection_method': 'rule',
                'total_confidence': 70,
                'risk_score': 88,
                'remediation': 'Use prepared statements',
            },
            {
                'type': 'XSS',
                'affected_url': 'http://example.com/comment.php?text=hello',
                'severity': 'Medium',
                'evidence': "<script>alert(1)</script> reflected",
                'detection_method': 'rule',
                'total_confidence': 65,
                'risk_score': 60,
                'remediation': 'Sanitize output',
            },
            {
                'type': 'Security Misconfiguration',
                'affected_url': 'http://example.com/',
                'severity': 'Low',
                'evidence': 'Missing HSTS, CSP headers',
                'detection_method': 'rule',
                'total_confidence': 90,
                'risk_score': 20,
                'remediation': 'Add security headers',
            },
        ]
    
    @pytest.fixture
    def sample_urls(self):
        """Sample scanned URLs."""
        return [
            'http://example.com/',
            'http://example.com/product.php?id=1',
            'http://example.com/list.php?cat=2',
            'http://example.com/search.php?q=test',
            'http://example.com/comment.php?text=hello',
            'http://example.com/about.php',
            'http://example.com/contact.php',
        ]
    
    # =========================================================================
    # Deduplication Tests
    # =========================================================================
    
    def test_deduplicates_same_vuln_type(self, engine, sample_findings, sample_urls):
        """Same vulnerability type should be grouped together."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        vulnerabilities = result['vulnerabilities']
        
        # 3 SQL Injection findings should become 1 deduplicated entry
        sql_vulns = [v for v in vulnerabilities if v['type'] == 'SQL Injection']
        assert len(sql_vulns) == 1
        
        # Should show 3 occurrences
        assert sql_vulns[0]['occurrences'] == 3
    
    def test_different_vuln_types_not_deduplicated(self, engine, sample_findings, sample_urls):
        """Different vulnerability types should remain separate."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        # Should have 3 unique vulnerability types: SQLi, XSS, Security Misconfiguration
        assert result['scan_summary']['total_unique_vulnerabilities'] == 3
    
    def test_affected_endpoints_tracked(self, engine, sample_findings, sample_urls):
        """All affected endpoints should be tracked."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        sql_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'SQL Injection')
        
        # Should have 3 affected endpoints
        assert len(sql_vuln['affected_endpoints']) == 3
        assert '/product.php?id' in sql_vuln['affected_endpoints']
        assert '/list.php?cat' in sql_vuln['affected_endpoints']
        assert '/search.php?q' in sql_vuln['affected_endpoints']
    
    def test_evidence_preserved(self, engine, sample_findings, sample_urls):
        """All evidence should be preserved."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        sql_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'SQL Injection')
        
        # All 3 pieces of evidence should be preserved
        assert len(sql_vuln['evidence']) == 3
    
    def test_max_confidence_used(self, engine, sample_findings, sample_urls):
        """Maximum confidence from group should be used."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        sql_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'SQL Injection')
        
        # Max confidence from the 3 findings (75, 80, 70) should be 80
        assert sql_vuln['confidence'] == 80
    
    def test_max_risk_used(self, engine, sample_findings, sample_urls):
        """Maximum risk score from group should be used."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        sql_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'SQL Injection')
        
        # Max risk from the 3 findings (90, 85, 88) should be 90
        assert sql_vuln['risk'] == 90
    
    # =========================================================================
    # Endpoint Tracking Tests
    # =========================================================================
    
    def test_total_endpoints_counted(self, engine, sample_findings, sample_urls):
        """Total scanned endpoints should be counted correctly."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        # 7 URLs scanned
        assert result['scan_summary']['total_endpoints_scanned'] == 7
    
    def test_raw_findings_count(self, engine, sample_findings, sample_urls):
        """Raw findings count should be preserved."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        # 5 raw findings
        assert result['scan_summary']['total_raw_findings'] == 5
    
    def test_endpoint_normalization(self, engine):
        """Endpoints should be normalized correctly."""
        endpoint1 = engine._extract_endpoint('http://example.com/page.php?id=1')
        endpoint2 = engine._extract_endpoint('http://example.com/page.php?id=999')
        
        # Should normalize to same endpoint (parameter name, not value)
        assert endpoint1 == endpoint2
        assert endpoint1 == '/page.php?id'
    
    def test_parameter_extraction(self, engine):
        """Parameters should be extracted correctly."""
        param = engine._extract_parameter('http://example.com/page.php?id=1&cat=2')
        assert 'id' in param
        assert 'cat' in param
    
    # =========================================================================
    # OWASP Mapping Tests
    # =========================================================================
    
    def test_owasp_mapping(self, engine, sample_findings, sample_urls):
        """OWASP categories should be mapped correctly."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        sql_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'SQL Injection')
        assert sql_vuln['owasp'] == 'A03:2021-Injection'
        
        security_vuln = next(v for v in result['vulnerabilities'] if v['type'] == 'Security Misconfiguration')
        assert security_vuln['owasp'] == 'A05:2021-Security-Misconfiguration'
    
    # =========================================================================
    # Statistics Tests
    # =========================================================================
    
    def test_statistics(self, engine, sample_findings, sample_urls):
        """Statistics should be calculated correctly."""
        engine.process_findings(sample_findings, sample_urls)
        stats = engine.get_statistics()
        
        assert stats['raw_findings_count'] == 5
        assert stats['deduplicated_count'] == 3
        assert stats['reduction_percentage'] == 40.0  # 5 -> 3 = 40% reduction
    
    # =========================================================================
    # Raw Findings Preservation Tests
    # =========================================================================
    
    def test_raw_findings_preserved(self, engine, sample_findings, sample_urls):
        """Raw findings should be preserved in output."""
        result = engine.process_findings(sample_findings, sample_urls)
        
        assert 'raw_findings' in result
        assert len(result['raw_findings']) == 5


class TestConvenienceFunctions:
    """Tests for helper functions."""
    
    def test_deduplicate_findings_function(self):
        """Test the convenience function works."""
        findings = [
            {'type': 'XSS', 'affected_url': 'http://example.com/a?x=1', 'severity': 'Medium', 'evidence': 'test', 'detection_method': 'rule'},
            {'type': 'XSS', 'affected_url': 'http://example.com/b?y=2', 'severity': 'Medium', 'evidence': 'test2', 'detection_method': 'rule'},
        ]
        urls = ['http://example.com/a?x=1', 'http://example.com/b?y=2']
        
        result = deduplicate_findings(findings, urls)
        
        assert result['scan_summary']['total_unique_vulnerabilities'] == 1
        assert result['vulnerabilities'][0]['occurrences'] == 2
    
    def test_format_report(self):
        """Test report formatting."""
        result = {
            'scan_summary': {
                'total_endpoints_scanned': 10,
                'total_raw_findings': 5,
                'total_unique_vulnerabilities': 2,
                'affected_endpoints_count': 3,
            },
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'owasp': 'A03:2021-Injection',
                    'root_cause': 'Unsanitized input',
                    'occurrences': 3,
                    'confidence': 80,
                    'affected_endpoints': ['/a', '/b', '/c'],
                }
            ],
        }
        
        report = format_report(result)
        
        assert 'SQL Injection' in report
        assert 'Total endpoints scanned: 10' in report
        assert 'Unique vulnerabilities: 2' in report


class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_findings(self):
        """Empty findings should not crash."""
        engine = DeduplicationEngine()
        result = engine.process_findings([], [])
        
        assert result['scan_summary']['total_unique_vulnerabilities'] == 0
        assert result['vulnerabilities'] == []
    
    def test_single_finding(self):
        """Single finding should work correctly."""
        engine = DeduplicationEngine()
        findings = [
            {'type': 'XSS', 'affected_url': 'http://test.com/x', 'severity': 'Medium', 'evidence': 'e', 'detection_method': 'rule'}
        ]
        result = engine.process_findings(findings, ['http://test.com/x'])
        
        assert result['scan_summary']['total_unique_vulnerabilities'] == 1
        assert result['vulnerabilities'][0]['occurrences'] == 1
    
    def test_url_without_query(self):
        """URLs without query strings should be handled."""
        engine = DeduplicationEngine()
        endpoint = engine._extract_endpoint('http://example.com/page.php')
        
        assert endpoint == '/page.php'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
