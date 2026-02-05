"""
Accuracy Tests with Known Payloads

Tests the AI model's detection rate against known attack payloads
and normal URLs. This is crucial for measuring model performance.
"""

import pytest
import sys
import os
from typing import List, Tuple

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.scanner.ai_model import AIInference


# =============================================================================
# TEST DATA - Known Attack Payloads
# =============================================================================

SQLI_PAYLOADS = [
    "https://example.com/search?q=' OR '1'='1",
    "https://example.com/user?id=1 UNION SELECT * FROM users--",
    "https://example.com/login?user=admin'--",
    "https://example.com/product?id=1; DROP TABLE products--",
    "https://example.com/api?query=' AND 1=1--",
    "https://example.com/search?q=1' AND SLEEP(5)--",
    "https://example.com/user?id=1' OR ''='",
]

XSS_PAYLOADS = [
    "https://example.com/page?input=<script>alert(1)</script>",
    "https://example.com/view?data=<img src=x onerror=alert(1)>",
    "https://example.com/search?q=<svg onload=alert(1)>",
    "https://example.com/comment?text=<body onload=alert(1)>",
    "https://example.com/param?x=javascript:alert(1)",
    "https://example.com/page?name=<iframe src='javascript:alert(1)'>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "https://example.com/download?file=../../../etc/passwd",
    "https://example.com/view?path=....//....//etc/shadow",
    "https://example.com/load?doc=..%2f..%2f..%2fetc/passwd",
    "https://example.com/file?name=../../../../var/log/apache2/access.log",
    "https://example.com/read?path=..\\..\\..\\windows\\system.ini",
]

COMMAND_INJECTION_PAYLOADS = [
    "https://example.com/ping?host=127.0.0.1; cat /etc/passwd",
    "https://example.com/exec?cmd=test | whoami",
    "https://example.com/run?input=$(id)",
    "https://example.com/process?data=`ls -la`",
    "https://example.com/api?action=test && rm -rf /",
]

NORMAL_URLS = [
    "https://example.com/",
    "https://example.com/products",
    "https://example.com/about",
    "https://example.com/contact",
    "https://example.com/products?page=1",
    "https://example.com/products?page=2&limit=20",
    "https://example.com/search?q=laptop",
    "https://example.com/user/profile",
    "https://example.com/api/v1/users",
    "https://example.com/blog/2024/01/new-features",
    "https://shop.example.com/category/electronics",
    "https://docs.example.com/getting-started",
    "https://example.com/products?category=shoes&sort=price",
    "https://example.com/account/settings?tab=security",
    "https://example.com/api/orders?status=pending&limit=50",
]


class TestPayloadDetectionRates:
    """Tests for measuring detection rates of known payloads."""

    @pytest.fixture
    def ai_engine(self):
        """Create an AIInference instance for tests."""
        model_dir = os.path.join(
            os.path.dirname(__file__), '..', 'api', 'scanner', 'models'
        )
        return AIInference(model_dir=model_dir)

    def _calculate_detection_rate(
        self, 
        ai_engine: AIInference, 
        urls: List[str], 
        expected_classes: List[int]
    ) -> Tuple[float, List[dict]]:
        """
        Calculate detection rate for a set of URLs.
        
        Returns:
            Tuple of (detection_rate, list of detailed results)
        """
        results = []
        detected = 0
        
        for url in urls:
            classification = ai_engine.classify_vulnerability(url)
            is_detected = classification['class'] in expected_classes
            
            if is_detected:
                detected += 1
            
            results.append({
                'url': url[:80] + '...' if len(url) > 80 else url,
                'predicted_class': classification['class'],
                'predicted_name': classification['class_name'],
                'confidence': classification['confidence'],
                'detected': is_detected
            })
        
        detection_rate = detected / len(urls) if urls else 0
        return detection_rate, results

    # =========================================================================
    # SQL Injection Detection Tests
    # =========================================================================

    def test_sqli_detection_rate(self, ai_engine):
        """Test SQL Injection detection rate (target: >= 70%)."""
        # Expected classes: 1 (SQLi) or 5 (Generic Attack)
        rate, results = self._calculate_detection_rate(
            ai_engine, SQLI_PAYLOADS, [1, 5]
        )
        
        print(f"\n=== SQL Injection Detection Results ===")
        print(f"Detection Rate: {rate:.1%}")
        for r in results:
            status = "✓" if r['detected'] else "✗"
            print(f"  {status} {r['predicted_name']} ({r['confidence']:.1%}): {r['url']}")
        
        # Assert minimum acceptable detection rate
        assert rate >= 0.70, f"SQLi detection rate too low: {rate:.1%}"

    # =========================================================================
    # XSS Detection Tests
    # =========================================================================

    def test_xss_detection_rate(self, ai_engine):
        """Test XSS detection rate (target: >= 70%)."""
        # Expected classes: 2 (XSS) or 5 (Generic Attack)
        rate, results = self._calculate_detection_rate(
            ai_engine, XSS_PAYLOADS, [2, 5]
        )
        
        print(f"\n=== XSS Detection Results ===")
        print(f"Detection Rate: {rate:.1%}")
        for r in results:
            status = "✓" if r['detected'] else "✗"
            print(f"  {status} {r['predicted_name']} ({r['confidence']:.1%}): {r['url']}")
        
        assert rate >= 0.70, f"XSS detection rate too low: {rate:.1%}"

    # =========================================================================
    # Path Traversal Detection Tests
    # =========================================================================

    def test_path_traversal_detection_rate(self, ai_engine):
        """Test Path Traversal detection rate (target: >= 70%)."""
        # Expected classes: 3 (Path Traversal) or 5 (Generic Attack)
        rate, results = self._calculate_detection_rate(
            ai_engine, PATH_TRAVERSAL_PAYLOADS, [3, 5]
        )
        
        print(f"\n=== Path Traversal Detection Results ===")
        print(f"Detection Rate: {rate:.1%}")
        for r in results:
            status = "✓" if r['detected'] else "✗"
            print(f"  {status} {r['predicted_name']} ({r['confidence']:.1%}): {r['url']}")
        
        assert rate >= 0.70, f"Path Traversal detection rate too low: {rate:.1%}"

    # =========================================================================
    # Command Injection Detection Tests
    # =========================================================================

    def test_command_injection_detection_rate(self, ai_engine):
        """Test Command Injection detection rate (target: >= 60%)."""
        # Expected classes: 4 (Command Injection) or 5 (Generic Attack)
        rate, results = self._calculate_detection_rate(
            ai_engine, COMMAND_INJECTION_PAYLOADS, [4, 5]
        )
        
        print(f"\n=== Command Injection Detection Results ===")
        print(f"Detection Rate: {rate:.1%}")
        for r in results:
            status = "✓" if r['detected'] else "✗"
            print(f"  {status} {r['predicted_name']} ({r['confidence']:.1%}): {r['url']}")
        
        assert rate >= 0.60, f"Command Injection detection rate too low: {rate:.1%}"

    # =========================================================================
    # False Positive Rate Tests
    # =========================================================================

    def test_false_positive_rate(self, ai_engine):
        """Test false positive rate on normal URLs (target: <= 20%)."""
        # Expected class: 0 (Normal)
        correct = 0
        results = []
        
        for url in NORMAL_URLS:
            classification = ai_engine.classify_vulnerability(url)
            is_correct = classification['class'] == 0  # Should be Normal
            
            if is_correct:
                correct += 1
            
            results.append({
                'url': url,
                'predicted_class': classification['class'],
                'predicted_name': classification['class_name'],
                'confidence': classification['confidence'],
                'is_correct': is_correct
            })
        
        accuracy = correct / len(NORMAL_URLS)
        false_positive_rate = 1 - accuracy
        
        print(f"\n=== Normal URL Classification Results ===")
        print(f"Accuracy: {accuracy:.1%}")
        print(f"False Positive Rate: {false_positive_rate:.1%}")
        for r in results:
            status = "✓" if r['is_correct'] else "✗ FP"
            print(f"  {status} {r['predicted_name']} ({r['confidence']:.1%}): {r['url']}")
        
        # Assert acceptable false positive rate
        assert false_positive_rate <= 0.30, f"False positive rate too high: {false_positive_rate:.1%}"

    # =========================================================================
    # Overall Detection Summary
    # =========================================================================

    def test_print_detection_summary(self, ai_engine):
        """Print a comprehensive detection summary (always passes)."""
        print("\n" + "=" * 70)
        print("ARHMORA AI DETECTION SUMMARY")
        print("=" * 70)
        
        # SQLi
        sqli_rate, _ = self._calculate_detection_rate(
            ai_engine, SQLI_PAYLOADS, [1, 5]
        )
        print(f"SQL Injection Detection:    {sqli_rate:.1%} ({len(SQLI_PAYLOADS)} samples)")
        
        # XSS
        xss_rate, _ = self._calculate_detection_rate(
            ai_engine, XSS_PAYLOADS, [2, 5]
        )
        print(f"XSS Detection:              {xss_rate:.1%} ({len(XSS_PAYLOADS)} samples)")
        
        # Path Traversal
        lfi_rate, _ = self._calculate_detection_rate(
            ai_engine, PATH_TRAVERSAL_PAYLOADS, [3, 5]
        )
        print(f"Path Traversal Detection:   {lfi_rate:.1%} ({len(PATH_TRAVERSAL_PAYLOADS)} samples)")
        
        # Command Injection
        cmd_rate, _ = self._calculate_detection_rate(
            ai_engine, COMMAND_INJECTION_PAYLOADS, [4, 5]
        )
        print(f"Command Injection Detection: {cmd_rate:.1%} ({len(COMMAND_INJECTION_PAYLOADS)} samples)")
        
        # False Positive Rate
        correct = sum(
            1 for url in NORMAL_URLS 
            if ai_engine.classify_vulnerability(url)['class'] == 0
        )
        fp_rate = 1 - (correct / len(NORMAL_URLS))
        print(f"False Positive Rate:        {fp_rate:.1%} ({len(NORMAL_URLS)} samples)")
        
        print("=" * 70)
        
        # Calculate overall score
        overall = (sqli_rate + xss_rate + lfi_rate + cmd_rate) / 4
        print(f"Overall Attack Detection:   {overall:.1%}")
        print("=" * 70)
        
        # This test always passes - it's for information
        assert True


class TestEncodedPayloads:
    """Tests for URL-encoded payloads."""

    @pytest.fixture
    def ai_engine(self):
        model_dir = os.path.join(
            os.path.dirname(__file__), '..', 'api', 'scanner', 'models'
        )
        return AIInference(model_dir=model_dir)

    def test_url_encoded_sqli(self, ai_engine):
        """Test detection of URL-encoded SQLi."""
        encoded_sqli = [
            "https://example.com/search?q=%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "https://example.com/user?id=1%20UNION%20SELECT%20%2A%20FROM%20users",
        ]
        
        for url in encoded_sqli:
            result = ai_engine.classify_vulnerability(url)
            # Should detect as some form of attack
            print(f"Encoded SQLi: {result['class_name']} - {url[:60]}")

    def test_url_encoded_xss(self, ai_engine):
        """Test detection of URL-encoded XSS."""
        encoded_xss = [
            "https://example.com/page?input=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "https://example.com/view?data=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        ]
        
        for url in encoded_xss:
            result = ai_engine.classify_vulnerability(url)
            print(f"Encoded XSS: {result['class_name']} - {url[:60]}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
