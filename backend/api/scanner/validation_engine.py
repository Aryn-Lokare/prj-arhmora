"""
Automated Vulnerability Validation Engine.

Runs after initial AI detection to validate findings using controlled payloads.
Supports: SQL Injection, XSS, LFI, Command Injection.
"""

import time
import logging
from typing import Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

logger = logging.getLogger(__name__)


class ValidationEngine:
    """Execute controlled validation payloads to confirm vulnerabilities."""

    # Validation payload pairs
    PAYLOADS = {
        'sql_boolean': {
            'true_payload': "' AND '1'='1",
            'false_payload': "' AND '1'='2",
            'description': 'Boolean-based SQL injection validation',
        },
        'sql_time': {
            'payload': "' AND SLEEP(5)--",
            'expected_delay_ms': 5000,
            'description': 'Time-based SQL injection validation',
        },
        'xss_script': {
            'payload': '<script>alert(1)</script>',
            'description': 'Basic XSS script injection',
        },
        'xss_event': {
            'payload': '<img src=x onerror=alert(1)>',
            'description': 'Event-based XSS injection',
        },
        'lfi_unix': {
            'payload': '../../../../../../etc/passwd',
            'signature': 'root:',
            'description': 'Unix passwd file disclosure',
        },
        'lfi_windows': {
            'payload': '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'signature': '127.0.0.1',
            'description': 'Windows hosts file disclosure',
        },
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certs
        # Suppress SSL warnings
        requests.packages.urllib3.disable_warnings()

    def validate_sql_injection(self, url: str, param: str = None) -> Dict:
        """
        Validate SQL injection using boolean differential.
        
        Sends ' AND 1=1 and ' AND 1=2, comparing response differences.
        """
        result = {
            'type': 'boolean_sqli',
            'validated': False,
            'differential_confirmed': False,
            'details': {},
        }

        try:
            # Get baseline
            baseline = self._make_request(url)
            if not baseline:
                return result

            # Inject true payload
            true_url = self._inject_payload(url, self.PAYLOADS['sql_boolean']['true_payload'], param)
            true_response = self._make_request(true_url)

            # Inject false payload
            false_url = self._inject_payload(url, self.PAYLOADS['sql_boolean']['false_payload'], param)
            false_response = self._make_request(false_url)

            if true_response and false_response:
                # Compare responses
                true_len = len(true_response.get('body', ''))
                false_len = len(false_response.get('body', ''))

                # Significant difference indicates boolean SQLi
                len_diff = abs(true_len - false_len)
                status_diff = true_response.get('status_code') != false_response.get('status_code')
                
                if len_diff > 100 or status_diff:
                    result['validated'] = True
                    result['differential_confirmed'] = True
                    result['details'] = {
                        'true_response_length': true_len,
                        'false_response_length': false_len,
                        'length_difference': len_diff,
                        'status_changed': status_diff,
                    }

        except Exception as e:
            logger.warning(f"SQL validation error: {e}")
            result['error'] = str(e)

        return result

    def validate_time_based_sqli(self, url: str, param: str = None) -> Dict:
        """
        Validate time-based SQL injection using SLEEP.
        """
        result = {
            'type': 'time_sqli',
            'validated': False,
            'delay_ms': 0,
            'expected_delay_ms': 5000,
        }

        try:
            # Baseline timing
            start = time.time()
            self._make_request(url)
            baseline_time = (time.time() - start) * 1000

            # Inject delay payload
            delay_url = self._inject_payload(url, self.PAYLOADS['sql_time']['payload'], param)
            start = time.time()
            self._make_request(delay_url)
            delay_time = (time.time() - start) * 1000

            actual_delay = delay_time - baseline_time
            result['delay_ms'] = int(actual_delay)
            result['baseline_ms'] = int(baseline_time)

            # If delay is at least 80% of expected, consider validated
            if actual_delay >= 4000:  # 4 seconds
                result['validated'] = True

        except Exception as e:
            logger.warning(f"Time-based SQLi validation error: {e}")
            result['error'] = str(e)

        return result

    def validate_xss(self, url: str, param: str = None) -> Dict:
        """
        Validate XSS by checking if payload is reflected unescaped.
        """
        result = {
            'type': 'xss_reflection',
            'validated': False,
            'payload_reflected': False,
            'unescaped': False,
        }

        try:
            payload = self.PAYLOADS['xss_script']['payload']
            test_url = self._inject_payload(url, payload, param)
            response = self._make_request(test_url)

            if response:
                body = response.get('body', '')
                # Check if payload is reflected
                if payload in body:
                    result['payload_reflected'] = True
                    result['unescaped'] = True
                    result['validated'] = True
                elif payload.replace('<', '&lt;').replace('>', '&gt;') in body:
                    # Escaped - not exploitable but reflected
                    result['payload_reflected'] = True
                    result['unescaped'] = False

        except Exception as e:
            logger.warning(f"XSS validation error: {e}")
            result['error'] = str(e)

        return result

    def validate_lfi(self, url: str, param: str = None) -> Dict:
        """
        Validate LFI by checking for signature file contents.
        """
        result = {
            'type': 'lfi',
            'validated': False,
            'file_content_detected': False,
        }

        try:
            # Try Unix passwd file
            lfi_url = self._inject_payload(url, self.PAYLOADS['lfi_unix']['payload'], param)
            response = self._make_request(lfi_url)

            if response:
                body = response.get('body', '')
                if self.PAYLOADS['lfi_unix']['signature'] in body:
                    result['validated'] = True
                    result['file_content_detected'] = True
                    result['file'] = '/etc/passwd'
                    return result

            # Try Windows hosts file
            lfi_url = self._inject_payload(url, self.PAYLOADS['lfi_windows']['payload'], param)
            response = self._make_request(lfi_url)

            if response:
                body = response.get('body', '')
                if self.PAYLOADS['lfi_windows']['signature'] in body:
                    result['validated'] = True
                    result['file_content_detected'] = True
                    result['file'] = 'windows/hosts'

        except Exception as e:
            logger.warning(f"LFI validation error: {e}")
            result['error'] = str(e)

        return result

    def validate_finding(self, v_type: str, url: str) -> Dict:
        """
        Validate a finding based on its vulnerability type.
        
        Returns validation result dict with 'validated' key and details.
        """
        if v_type in ['SQL Injection', 'SQLi']:
            result = self.validate_sql_injection(url)
            if not result.get('validated'):
                result = self.validate_time_based_sqli(url)
            return result
        
        elif v_type in ['Reflected XSS', 'XSS', 'Cross-Site Scripting']:
            return self.validate_xss(url)
        
        elif v_type in ['LFI', 'Path Traversal', 'Local File Inclusion']:
            return self.validate_lfi(url)
        
        else:
            return {'type': 'unsupported', 'validated': False, 'message': f'No validation for {v_type}'}

    def _inject_payload(self, url: str, payload: str, param: str = None) -> str:
        """Inject payload into URL query string."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if param and param in query_params:
            # Inject into specific parameter
            query_params[param] = [query_params[param][0] + payload]
        elif query_params:
            # Inject into first parameter
            first_key = list(query_params.keys())[0]
            query_params[first_key] = [query_params[first_key][0] + payload]
        else:
            # Append to URL path
            return url + payload

        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _make_request(self, url: str) -> Optional[Dict]:
        """Make HTTP request and return response data."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            return {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'body': response.text[:10000],  # Limit body size
                'headers': dict(response.headers),
            }
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
