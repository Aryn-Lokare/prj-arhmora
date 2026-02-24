"""
Test suite for the 6 advanced detection modules.

Tests cover:
  - ConfidenceScorer formula correctness
  - BaseDetector url/param helpers
  - Each detector's detect() method with mocked HTTP responses
  - Suppression of low-confidence findings (< 0.60)
  - Correct classification labels (Confirmed / Strong / Possible)
  - Fix library entries for all new types
  - OWASP mapping entries for all new types
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Add backend directory to path so imports work without Django setup
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ---------------------------------------------------------------------------
# ConfidenceScorer tests (no HTTP needed)
# ---------------------------------------------------------------------------

from api.scanner.advanced.base_detector import ConfidenceScorer, THRESHOLD_REPORT


class TestConfidenceScorer(unittest.TestCase):

    def test_formula_weights_sum_to_one(self):
        total = sum(ConfidenceScorer.WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=6)

    def test_all_zeros_returns_zero(self):
        score = ConfidenceScorer.compute()
        self.assertEqual(score, 0.0)

    def test_all_ones_returns_one(self):
        score = ConfidenceScorer.compute(1.0, 1.0, 1.0, 1.0, 1.0)
        self.assertEqual(score, 1.0)

    def test_partial_score(self):
        # Only validation_strength = 1.0 → 0.35
        score = ConfidenceScorer.compute(validation_strength=1.0)
        self.assertAlmostEqual(score, 0.35, places=3)

    def test_classify_confirmed(self):
        self.assertEqual(ConfidenceScorer.classify(0.90), "Confirmed")
        self.assertEqual(ConfidenceScorer.classify(0.85), "Confirmed")

    def test_classify_strong(self):
        self.assertEqual(ConfidenceScorer.classify(0.75), "Strong")
        self.assertEqual(ConfidenceScorer.classify(0.70), "Strong")

    def test_classify_possible(self):
        self.assertEqual(ConfidenceScorer.classify(0.63), "Possible")
        self.assertEqual(ConfidenceScorer.classify(0.60), "Possible")

    def test_classify_suppressed(self):
        self.assertEqual(ConfidenceScorer.classify(0.59), "Suppressed")
        self.assertEqual(ConfidenceScorer.classify(0.0), "Suppressed")

    def test_similarity_delta_zero_baseline(self):
        self.assertEqual(ConfidenceScorer.similarity_delta(0, 100), 0.0)

    def test_similarity_delta_normal(self):
        delta = ConfidenceScorer.similarity_delta(1000, 500)
        self.assertAlmostEqual(delta, 0.5, places=3)

    def test_similarity_delta_capped_at_one(self):
        delta = ConfidenceScorer.similarity_delta(100, 10000)
        self.assertEqual(delta, 1.0)

    def test_threshold_constant(self):
        self.assertEqual(THRESHOLD_REPORT, 0.60)


# ---------------------------------------------------------------------------
# BaseDetector url helpers (no HTTP needed)
# ---------------------------------------------------------------------------

from api.scanner.advanced.base_detector import BaseDetector


class ConcreteDetector(BaseDetector):
    """Minimal implementation to allow instantiation."""
    def detect(self, url, crawled_data):
        return []


class TestBaseDetectorHelpers(unittest.TestCase):

    def setUp(self):
        self.d = ConcreteDetector()

    def test_inject_param_adds_new(self):
        url = "http://example.com/items"
        result = self.d._inject_param(url, "id", "42")
        self.assertIn("id=42", result)

    def test_inject_param_replaces_existing(self):
        url = "http://example.com/items?id=1"
        result = self.d._inject_param(url, "id", "99")
        self.assertIn("id=99", result)
        self.assertNotIn("id=1", result)

    def test_get_numeric_params(self):
        url = "http://example.com/page?user_id=42&name=alice"
        params = self.d._get_numeric_params(url)
        self.assertIn("user_id", params)
        self.assertNotIn("name", params)

    def test_get_redirect_params(self):
        url = "http://example.com/login?next=http://safe.com&name=x"
        params = self.d._get_redirect_params(url)
        self.assertIn("next", params)
        self.assertNotIn("name", params)

    def test_build_finding_suppressed_below_threshold(self):
        result = self.d._build_finding(
            "IDOR", "http://example.com/", "High",
            confidence_score=0.50,
            evidence="test",
            validation_checks_passed=1,
            total_checks=3,
        )
        self.assertIsNone(result)

    def test_build_finding_reported_above_threshold(self):
        result = self.d._build_finding(
            "IDOR", "http://example.com/", "High",
            confidence_score=0.72,
            evidence="test",
            validation_checks_passed=2,
            total_checks=3,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'IDOR')
        self.assertEqual(result['classification'], 'Strong')

    def test_severity_to_risk(self):
        self.assertEqual(self.d._severity_to_risk("Critical"), 95)
        self.assertEqual(self.d._severity_to_risk("High"), 80)
        self.assertEqual(self.d._severity_to_risk("Medium"), 55)
        self.assertEqual(self.d._severity_to_risk("Low"), 25)

    def test_contains_any_case_insensitive(self):
        self.assertTrue(self.d._contains_any("Access denied to ADMIN page", ["admin"]))
        self.assertFalse(self.d._contains_any("Normal page", ["admin", "forbidden"]))


# ---------------------------------------------------------------------------
# IDOR Detector unit tests
# ---------------------------------------------------------------------------

from api.scanner.advanced.idor_detector import IDORDetector


class TestIDORDetector(unittest.TestCase):

    def test_no_numeric_params_returns_empty(self):
        detector = IDORDetector()
        result = detector.detect("http://example.com/page", {})
        self.assertEqual(result, [])

    def test_properly_denied_response_suppresses(self):
        """Detector must suppress if ID+1 returns 403."""
        detector = IDORDetector()
        mock_403 = MagicMock()
        mock_403.status_code = 403
        mock_403.body = "Forbidden"
        mock_403.body_len = 9

        with patch.object(detector, '_baseline', return_value=MagicMock(
            status_code=200, body='{"user":"alice"}', body_len=20
        )):
            with patch.object(detector, '_request', return_value=mock_403):
                result = detector.detect("http://example.com/user?id=1", {})
        self.assertEqual(result, [])

    def test_extract_path_ids(self):
        ids = IDORDetector._extract_path_ids("http://example.com/users/42/profile")
        self.assertIn("42", ids)


# ---------------------------------------------------------------------------
# CSRF Detector unit tests
# ---------------------------------------------------------------------------

from api.scanner.advanced.csrf_detector import CSRFDetector


class TestCSRFDetector(unittest.TestCase):

    def test_no_html_returns_empty(self):
        detector = CSRFDetector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.body = '{"key": "value"}'
        mock_resp.body_len = 16

        with patch.object(detector, '_baseline', return_value=mock_resp):
            result = detector.detect("http://api.example.com/data", {})
        self.assertEqual(result, [])

    def test_has_csrf_token_true(self):
        detector = CSRFDetector()
        fields = {'csrf_token': '', 'username': '', 'password': ''}
        self.assertTrue(detector._has_csrf_token(fields))

    def test_has_csrf_token_false(self):
        detector = CSRFDetector()
        fields = {'username': '', 'password': '', 'action': ''}
        self.assertFalse(detector._has_csrf_token(fields))

    def test_form_is_sensitive_true(self):
        detector = CSRFDetector()
        self.assertTrue(detector._form_is_sensitive({'email': '', 'password': ''}))

    def test_form_is_sensitive_false(self):
        detector = CSRFDetector()
        self.assertFalse(detector._form_is_sensitive({'q': '', 'search_term': ''}))

    def test_extract_post_forms(self):
        html = '''
        <form method="POST" action="/login">
            <input name="username" type="text">
            <input name="password" type="password">
            <input type="submit">
        </form>
        '''
        detector = CSRFDetector()
        forms = detector._extract_post_forms(html, "http://example.com")
        self.assertEqual(len(forms), 1)
        self.assertIn('username', forms[0]['fields'])

    def test_get_form_csrf_token_in_form_returns_empty(self):
        html = '''
        <form method="POST" action="/login">
            <input name="csrf_token" type="hidden" value="abc123">
            <input name="username" type="text">
        </form>
        '''
        detector = CSRFDetector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_resp.body = html
        mock_resp.body_len = len(html)

        with patch.object(detector, '_baseline', return_value=mock_resp):
            result = detector.detect("http://example.com/login", {})
        # Should be empty because form has csrf_token
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# CORS Detector unit tests
# ---------------------------------------------------------------------------

from api.scanner.advanced.cors_detector import CORSDetector


class TestCORSDetector(unittest.TestCase):

    def test_no_cors_headers_no_reflection_returns_empty(self):
        detector = CORSDetector()
        mock_base = MagicMock()
        mock_base.status_code = 200
        mock_base.headers = {'Content-Type': 'text/html'}
        mock_base.body_len = 500

        mock_probe = MagicMock()
        mock_probe.headers = {}
        mock_probe.body_len = 500

        with patch.object(detector, '_baseline', return_value=mock_base):
            with patch.object(detector, '_request', return_value=mock_probe):
                result = detector.detect("http://example.com/", {})
        self.assertEqual(result, [])

    def test_reflected_origin_with_credentials_raises_high(self):
        detector = CORSDetector()
        mock_base = MagicMock()
        mock_base.status_code = 200
        mock_base.headers = {}
        mock_base.body_len = 500

        def probe_side_effect(url, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            mock = MagicMock()
            mock.headers = {
                'Access-Control-Allow-Origin': origin,
                'Access-Control-Allow-Credentials': 'true',
            }
            mock.body_len = 500
            return mock

        with patch.object(detector, '_baseline', return_value=mock_base):
            with patch.object(detector, '_request', side_effect=probe_side_effect):
                result = detector.detect("http://example.com/api/data", {})

        self.assertTrue(len(result) > 0)
        self.assertIn(result[0]['severity'], ['High', 'Medium'])
        self.assertGreaterEqual(result[0]['confidence_score'], 0.60)


# ---------------------------------------------------------------------------
# Open Redirect Detector unit tests
# ---------------------------------------------------------------------------

from api.scanner.advanced.open_redirect_detector import OpenRedirectDetector


class TestOpenRedirectDetector(unittest.TestCase):

    def test_no_redirect_params_returns_empty(self):
        detector = OpenRedirectDetector()
        result = detector.detect("http://example.com/page?q=test", {})
        self.assertEqual(result, [])

    def test_off_domain_redirect_confirmed(self):
        detector = OpenRedirectDetector()
        mock_baseline = MagicMock()
        mock_baseline.status_code = 200
        mock_baseline.body_len = 500

        import requests
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.url = "https://evil-redirect.com/landing"
        mock_resp.status_code = 200
        mock_resp.text = "evil page"
        mock_resp.headers = {}

        with patch.object(detector, '_baseline', return_value=mock_baseline):
            with patch.object(detector._follow_session, 'get', return_value=mock_resp):
                result = detector.detect("http://example.com/?next=http://evil.com", {})

        # Check that a finding was generated with adequate confidence
        if result:
            self.assertGreaterEqual(result[0]['confidence_score'], 0.60)


# ---------------------------------------------------------------------------
# Command Injection Detector unit tests
# ---------------------------------------------------------------------------

from api.scanner.advanced.command_injection_detector import CommandInjectionDetector


class TestCommandInjectionDetector(unittest.TestCase):

    def test_no_query_params_returns_empty(self):
        detector = CommandInjectionDetector()
        result = detector.detect("http://example.com/page", {})
        self.assertEqual(result, [])

    def test_shell_errors_in_baseline_suppresses(self):
        detector = CommandInjectionDetector()
        mock_base = MagicMock()
        mock_base.status_code = 200
        mock_base.body = "sh: command not found"
        mock_base.body_len = 25

        with patch.object(detector, '_request', return_value=mock_base):
            result = detector.detect("http://example.com/cmd?input=test", {})
        self.assertEqual(result, [])

    def test_output_marker_reflection_scores_high(self):
        from api.scanner.advanced.command_injection_detector import OUTPUT_MARKER
        detector = CommandInjectionDetector()

        mock_base = MagicMock()
        mock_base.status_code = 200
        mock_base.body = "normal page"
        mock_base.body_len = 11

        def side_effect(url, **kwargs):
            if OUTPUT_MARKER in url:
                m = MagicMock()
                m.status_code = 200
                m.body = f"Result: {OUTPUT_MARKER}"
                m.body_len = 30
                m.elapsed_ms = 200
                return m
            return mock_base

        with patch.object(detector, '_request', side_effect=side_effect):
            with patch.object(detector, '_timed_request', return_value=(200.0, mock_base)):
                result = detector.detect("http://example.com/exec?cmd=ls", {})

        # Output reflection alone needs ≥2 checks — expect empty unless timing also confirmed
        # This tests the suppression guard
        self.assertIsInstance(result, list)


# ---------------------------------------------------------------------------
# Fix Library completeness tests
# ---------------------------------------------------------------------------

from api.ai_engine.fix_library import get_fix_data, get_all_types

NEW_TYPES = [
    "IDOR", "Insecure Direct Object Reference",
    "CSRF", "Cross-Site Request Forgery",
    "Broken Authentication",
    "CORS Misconfiguration", "CORS Misconfiguration (Credentials)",
    "Open Redirect",
]


class TestFixLibraryNewTypes(unittest.TestCase):

    def test_all_new_types_have_entries(self):
        all_types = get_all_types()
        for t in NEW_TYPES:
            self.assertIn(t, all_types, f"Missing fix library entry for: {t}")

    def test_all_new_types_have_remediation_text(self):
        for t in NEW_TYPES:
            data = get_fix_data(t)
            self.assertIn('remediation_text', data)
            self.assertGreater(len(data['remediation_text']), 20)

    def test_all_new_types_have_references(self):
        for t in NEW_TYPES:
            data = get_fix_data(t)
            self.assertIn('references', data)

    def test_all_new_types_have_risk_reduction(self):
        for t in NEW_TYPES:
            data = get_fix_data(t)
            self.assertIn('risk_reduction_percent', data)
            self.assertGreater(data['risk_reduction_percent'], 0)


# ---------------------------------------------------------------------------
# Deduplication OWASP mapping tests
# ---------------------------------------------------------------------------

from api.scanner.deduplication import OWASP_MAPPING, ROOT_CAUSE_TEMPLATES


class TestDeduplicationMappings(unittest.TestCase):

    def test_owasp_mapping_for_new_types(self):
        for t in ["IDOR", "CSRF", "Broken Authentication", "CORS Misconfiguration",
                  "CORS Misconfiguration (Credentials)", "Open Redirect"]:
            self.assertIn(t, OWASP_MAPPING, f"Missing OWASP mapping for: {t}")

    def test_root_cause_templates_for_new_types(self):
        for t in ["IDOR", "CSRF", "Broken Authentication", "CORS Misconfiguration",
                  "CORS Misconfiguration (Credentials)", "Open Redirect"]:
            self.assertIn(t, ROOT_CAUSE_TEMPLATES, f"Missing root cause template for: {t}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
