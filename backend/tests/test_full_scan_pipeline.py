"""
Integration Test for Full Scan Pipeline

Tests the VulnerabilityScanner class and its interaction with:
- AIInference
- FeatureExtractor
- ConfidenceEngine
- FixPrioritizer
- GeminiExplainer (Mocked)
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.scanner.scanners import VulnerabilityScanner


class TestFullScanPipeline:
    """Integration integrity for the full scan pipeline."""

    @pytest.fixture
    def scanner(self):
        """Create a VulnerabilityScanner instance with mocked components."""
        target = "https://example.com"
        scanner = VulnerabilityScanner(target)
        
        # Mock the GeminiExplainer to avoid API calls
        scanner.explainer = MagicMock()
        scanner.explainer.generate_explanation.return_value = {
            "non_technical": "Mocked explanation",
            "technical": "Mocked technical details"
        }
        
        return scanner

    @patch('api.scanner.scanners.requests.get')
    def test_run_scans_integration(self, mock_get, scanner):
        """Test running a full scan on a list of URLs."""
        # Mock HTTP responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Some content</body></html>"
        mock_response.headers = {'Server': 'Nginx'}
        mock_get.return_value = mock_response

        # Crawled data input
        crawled_data = {
            'visited_urls': [
                "https://example.com/login",
                "https://example.com/search?q=' OR 1=1--",  # SQLi
                "https://example.com/about"
            ]
        }

        print("Running full scan pipeline...")
        findings = scanner.run_scans(crawled_data)

        # Basic assertions
        assert isinstance(findings, list)
        assert len(findings) > 0

        # Check for expected finding types
        finding_types = [f['type'] for f in findings]
        print(f"Findings found: {finding_types}")

        # Should detect the SQLi via AI or Rule
        assert any("SQL Injection" in ft or "Anomaly" in ft for ft in finding_types)

        # Check if fields are populated correctly (New Architecture fields)
        first_finding = findings[0]
        required_fields = [
            'type', 'severity', 'affected_url', 'risk_score',
            'confidence', 'priority_rank'
        ]
        
        for field in required_fields:
            assert field in first_finding, f"Finding missing {field}"

    def test_risk_scoring_integration(self, scanner):
        """Test that risk scores are calculated and prioritized."""
        # Manually verify that prioritized rankings make sense
        # This requires adding findings manually and running prioritization
        
        scanner.findings = [
            {
                'type': 'Missing Headers', 
                'severity': 'Low', 
                'risk_score': 10,
                'confidence': 0.9,
                'endpoint_sensitivity': 'public',
                'affected_url': 'https://example.com',
                'evidence': '', 'remediation': ''
            },
            {
                'type': 'SQL Injection', 
                'severity': 'High', 
                'risk_score': 90,
                'confidence': 0.95,
                'endpoint_sensitivity': 'admin',
                'affected_url': 'https://example.com/admin',
                'evidence': '', 'remediation': ''
            }
        ]
        
        # Run prioritization
        from api.scanner.fix_prioritizer import FixPrioritizer
        prioritizer = FixPrioritizer()
        ranked_findings = prioritizer.rank_findings(scanner.findings)
        
        # SQLi should be rank 1 (highest priority)
        assert ranked_findings[0]['type'] == 'SQL Injection'
        assert ranked_findings[0]['priority_rank'] == 1
        
        # Missing Headers should be rank 2
        assert ranked_findings[1]['type'] == 'Missing Headers'
        assert ranked_findings[1]['priority_rank'] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
