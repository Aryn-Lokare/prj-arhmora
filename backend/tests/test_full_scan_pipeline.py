"""
Integration Test for Full Scan Pipeline — Armora v2

Tests the ArmoraScanner orchestrator:
- SmartDetectionEngine (Layer 1)
- GeminiExplainer (Layer 2, mocked)
- Finding enrichment
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from api.scanner.scanner import ArmoraScanner


class TestFullScanPipeline:
    """Integration tests for the Armora v2 scan pipeline."""

    @pytest.fixture
    def scanner(self):
        """Create an ArmoraScanner with mocked Gemini explainer."""
        scanner = ArmoraScanner("https://example.com")

        # Mock the GeminiExplainer to avoid real API calls
        scanner.explainer = MagicMock()
        scanner.explainer.enabled = False  # Skip Gemini layer entirely in unit tests

        return scanner

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_run_pipeline_returns_list(self, mock_request, scanner):
        """run() should always return a list, even on a simple page."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Hello</body></html>"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_request.return_value = mock_response

        crawled_data = {
            "visited_urls": ["https://example.com/"],
            "forms": [],
        }

        findings = scanner.run(crawled_data)
        assert isinstance(findings, list)

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_finding_has_required_fields(self, mock_request, scanner):
        """Every finding must have the required output fields."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Hello</body></html>"
        mock_response.headers = {}  # Missing security headers → will generate a finding
        mock_request.return_value = mock_response

        crawled_data = {
            "visited_urls": ["https://example.com/"],
            "forms": [],
        }

        findings = scanner.run(crawled_data)

        required_fields = ["type", "severity", "affected_url", "confidence", "status"]
        for finding in findings:
            for field in required_fields:
                assert field in finding, f"Finding missing field: {field}"

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_http_site_triggers_cryptographic_failure(self, mock_request, scanner):
        """An HTTP (non-HTTPS) target should produce a Cryptographic Failure finding."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        http_scanner = ArmoraScanner("http://example.com")
        http_scanner.explainer = MagicMock()
        http_scanner.explainer.enabled = False

        crawled_data = {"visited_urls": ["http://example.com/"], "forms": []}
        findings = http_scanner.run(crawled_data)

        finding_types = [f["type"] for f in findings]
        assert "Cryptographic Failure" in finding_types

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_missing_security_headers_detected(self, mock_request, scanner):
        """A response missing all security headers should produce a misconfiguration finding."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {}  # No security headers
        mock_request.return_value = mock_response

        crawled_data = {"visited_urls": ["https://example.com/"], "forms": []}
        findings = scanner.run(crawled_data)

        finding_types = [f["type"] for f in findings]
        assert "Security Misconfiguration" in finding_types

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_server_header_triggers_info_disclosure(self, mock_request, scanner):
        """A Server header in the response should be flagged as Information Disclosure."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {"Server": "Apache/2.4.1"}
        mock_request.return_value = mock_response

        crawled_data = {"visited_urls": ["https://example.com/"], "forms": []}
        findings = scanner.run(crawled_data)

        finding_types = [f["type"] for f in findings]
        assert "Information Disclosure" in finding_types

    @patch('api.scanner.utils.http_client.sync_requests.Session.request')
    def test_findings_have_severity_labels(self, mock_request, scanner):
        """Severity must be one of the expected labels."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        crawled_data = {"visited_urls": ["https://example.com/"], "forms": []}
        findings = scanner.run(crawled_data)

        valid_severities = {"Low", "Medium", "High", "Critical"}
        for finding in findings:
            assert finding["severity"] in valid_severities, (
                f"Unexpected severity: {finding['severity']}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
