"""
Unit Tests for Feature Extractor

Tests URL feature extraction, entropy calculation, and endpoint classification.
"""

import pytest
import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.scanner.feature_extractor import FeatureExtractor


class TestFeatureExtractor:
    """Unit tests for FeatureExtractor class."""

    @pytest.fixture
    def extractor(self):
        """Create a FeatureExtractor instance for tests."""
        return FeatureExtractor()

    # =========================================================================
    # URL Feature Extraction Tests
    # =========================================================================

    def test_extract_url_features_simple(self, extractor):
        """Test feature extraction from a simple URL."""
        url = "https://example.com/products?page=1"
        features = extractor.extract_url_features(url)

        assert 'url_length' in features
        assert 'path_length' in features
        assert 'query_length' in features
        assert 'url_entropy' in features
        assert 'special_char_count' in features

        assert features['url_length'] == len(url)
        assert features['query_length'] > 0  # Has query string

    def test_extract_url_features_no_query(self, extractor):
        """Test feature extraction from URL without query string."""
        url = "https://example.com/about"
        features = extractor.extract_url_features(url)

        assert features['query_length'] == 0
        assert features['param_count'] == 0

    def test_extract_url_features_sqli_url(self, extractor):
        """Test feature extraction from URL with SQLi payload."""
        url = "https://example.com/search?q=' OR '1'='1"
        features = extractor.extract_url_features(url)

        # SQLi URLs should have higher sql_char_count
        assert features['sql_char_count'] > 0
        assert "'" in url  # Verify the URL has single quotes

    def test_extract_url_features_xss_url(self, extractor):
        """Test feature extraction from URL with XSS payload."""
        url = "https://example.com/page?input=<script>alert(1)</script>"
        features = extractor.extract_url_features(url)

        # XSS URLs should have xss characters
        assert features['xss_char_count'] > 0

    def test_extract_url_features_path_traversal(self, extractor):
        """Test feature extraction from path traversal URL."""
        url = "https://example.com/download?file=../../../etc/passwd"
        features = extractor.extract_url_features(url)

        # Should have high path depth indicators
        assert features['special_char_count'] > 0

    # =========================================================================
    # Entropy Calculation Tests
    # =========================================================================

    def test_entropy_calculation_low(self, extractor):
        """Test entropy for a simple, repetitive string."""
        # Low entropy strings are predictable
        simple_url = "https://aaa.aaa/aaa"
        features = extractor.extract_url_features(simple_url)
        
        # Simple repetitive strings have lower entropy
        assert features['url_entropy'] < 4.0

    def test_entropy_calculation_high(self, extractor):
        """Test entropy for a complex, random-looking string."""
        complex_url = "https://example.com/xK9mZ2!@#$%^&*()_+{}|:<>?"
        features = extractor.extract_url_features(complex_url)
        
        # Complex strings with many unique characters have higher entropy
        assert features['url_entropy'] > 3.5

    # =========================================================================
    # Endpoint Sensitivity Classification Tests
    # =========================================================================

    def test_endpoint_sensitivity_admin(self, extractor):
        """Test admin endpoint detection."""
        admin_urls = [
            "https://example.com/admin",
            "https://example.com/administrator",
            "https://example.com/admin/users",
            "https://example.com/dashboard/admin",
        ]
        
        for url in admin_urls:
            label = extractor.get_endpoint_sensitivity_label(url)
            assert label == 'admin', f"Expected 'admin' for {url}, got {label}"

    def test_endpoint_sensitivity_auth(self, extractor):
        """Test authentication endpoint detection."""
        auth_urls = [
            "https://example.com/login",
            "https://example.com/signin",
            "https://example.com/auth/callback",
            "https://example.com/password/reset",
        ]
        
        for url in auth_urls:
            label = extractor.get_endpoint_sensitivity_label(url)
            assert label == 'auth', f"Expected 'auth' for {url}, got {label}"

    def test_endpoint_sensitivity_api(self, extractor):
        """Test API endpoint detection."""
        api_urls = [
            "https://example.com/api/users",
            "https://example.com/api/v1/products",
            "https://example.com/graphql",
        ]
        
        for url in api_urls:
            label = extractor.get_endpoint_sensitivity_label(url)
            assert label == 'api', f"Expected 'api' for {url}, got {label}"

    def test_endpoint_sensitivity_public(self, extractor):
        """Test public endpoint detection."""
        public_urls = [
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/products",
            "https://example.com/blog/article",
        ]
        
        for url in public_urls:
            label = extractor.get_endpoint_sensitivity_label(url)
            assert label == 'public', f"Expected 'public' for {url}, got {label}"

    # =========================================================================
    # Unified Feature Vector Tests
    # =========================================================================

    def test_get_unified_feature_vector_length(self, extractor):
        """Test that unified feature vector has consistent length."""
        urls = [
            "https://example.com/",
            "https://example.com/products?page=1",
            "https://example.com/search?q=' OR 1=1--",
        ]
        
        vectors = [extractor.get_unified_feature_vector(url) for url in urls]
        
        # All vectors should have the same length
        lengths = [len(v) for v in vectors]
        assert len(set(lengths)) == 1, f"Inconsistent vector lengths: {lengths}"

    def test_get_feature_dict(self, extractor):
        """Test feature dictionary contains all expected keys."""
        url = "https://example.com/page?id=123"
        features = extractor.get_feature_dict(url)

        expected_keys = [
            'url_length', 'path_length', 'query_length', 
            'url_entropy', 'special_char_count'
        ]
        
        for key in expected_keys:
            assert key in features, f"Missing key: {key}"


class TestFeatureEdgeCases:
    """Edge case tests for FeatureExtractor."""

    @pytest.fixture
    def extractor(self):
        return FeatureExtractor()

    def test_empty_url(self, extractor):
        """Test handling of empty URL."""
        features = extractor.extract_url_features("")
        
        assert features['url_length'] == 0
        assert features['url_entropy'] == 0.0

    def test_url_with_unicode(self, extractor):
        """Test handling of URL with unicode characters."""
        url = "https://example.com/search?q=café"
        features = extractor.extract_url_features(url)
        
        # Should not crash and produce valid features
        assert features['url_length'] > 0

    def test_very_long_url(self, extractor):
        """Test handling of very long URL."""
        long_payload = "A" * 5000
        url = f"https://example.com/page?data={long_payload}"
        features = extractor.extract_url_features(url)
        
        assert features['url_length'] > 5000

    def test_url_with_encoded_characters(self, extractor):
        """Test handling of URL-encoded characters."""
        url = "https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
        features = extractor.extract_url_features(url)
        
        assert features['has_encoded_chars'] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
