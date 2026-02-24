import unittest
from unittest.mock import MagicMock, patch
import json
from api.scanner.evidence_collector import EvidenceCollector

class TestEvidenceCollector(unittest.TestCase):

    def setUp(self):
        self.collector = EvidenceCollector()
        # Mock the session to prevent actual HTTP requests
        self.collector.session = MagicMock()

    def test_capture_http_evidence_success(self):
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = '<html><body>Hello World</body></html>'
        mock_response.cookies = {'sessionid': '12345'}
        self.collector.session.request.return_value = mock_response

        evidence = self.collector.capture_http_evidence(
            url='http://example.com',
            method='GET'
        )

        self.assertEqual(evidence['evidence_type'], 'http_capture')
        self.assertIn('timestamp', evidence)
        self.assertEqual(evidence['request']['url'], 'http://example.com')
        self.assertEqual(evidence['response']['status_code'], 200)
        self.assertEqual(evidence['response']['body'], '<html><body>Hello World</body></html>')
        self.assertEqual(evidence['response']['cookies'], {'sessionid': '12345'})

    def test_capture_xss_proof_reflected(self):
        # Mock HTTP capture
        self.collector.capture_http_evidence = MagicMock(return_value={
            'evidence_type': 'http_capture',
            'response': {'body': '<html>Search: <script>alert(1)</script></html>'}
        })

        url = 'http://example.com/search?q=<script>alert(1)</script>'
        payload = '<script>alert(1)</script>'
        
        evidence = self.collector.capture_xss_proof(url, payload)

        self.assertEqual(evidence['evidence_type'], 'xss_proof')
        self.assertTrue(evidence['exploitation_proof']['payload_reflected'])
        self.assertTrue(evidence['exploitation_proof']['reflected_unescaped'])
        self.assertIn('Confirmed XSS', evidence['exploitation_proof']['risk_assessment'])

    def test_capture_xss_proof_encoded(self):
        # Mock HTTP capture
        self.collector.capture_http_evidence = MagicMock(return_value={
            'evidence_type': 'http_capture',
            'response': {'body': '<html>Search: &lt;script&gt;alert(1)&lt;/script&gt;</html>'}
        })

        url = 'http://example.com/search?q=<script>alert(1)</script>'
        payload = '<script>alert(1)</script>'
        
        evidence = self.collector.capture_xss_proof(url, payload)

        self.assertTrue(evidence['exploitation_proof']['payload_reflected'])
        self.assertFalse(evidence['exploitation_proof']['reflected_unescaped'])
        self.assertIn('mitigated', evidence['exploitation_proof']['risk_assessment'])

    def test_capture_sqli_proof_boolean(self):
        # Mock capture_http_evidence to return different responses
        def side_effect(url, payload):
            if payload == "' AND '1'='1":
                return {'response': {'body': 'Article 1 Content'}}
            else:
                return {'response': {'body': ''}}
        
        self.collector.capture_http_evidence = MagicMock(side_effect=side_effect)

        evidence = self.collector.capture_sqli_proof(
            url='http://example.com/article?id=1',
            true_payload="' AND '1'='1",
            false_payload="' AND '1'='2"
        )

        self.assertEqual(evidence['evidence_type'], 'sqli_boolean_proof')
        self.assertTrue(evidence['exploitation_proof']['differential_analysis']['content_differs'])
        self.assertIn('Likely SQLi', evidence['exploitation_proof']['risk_assessment'])

    def test_get_evidence_summary(self):
        evidence = {
            'evidence_type': 'sqli_boolean_proof',
            'timestamp': '2024-01-01T12:00:00Z',
            'request': {'method': 'GET', 'url': 'http://test.com'},
            'response': {'status_code': 200, 'response_time_ms': 150},
            'exploitation_proof': {'risk_assessment': 'Confirmed SQLi'}
        }
        
        summary = self.collector.get_evidence_summary(evidence)
        
        self.assertIn('Evidence Type: sqli_boolean_proof', summary)
        self.assertIn('Response: 200', summary)
        self.assertIn('Assessment: Confirmed SQLi', summary)

if __name__ == '__main__':
    unittest.main()
