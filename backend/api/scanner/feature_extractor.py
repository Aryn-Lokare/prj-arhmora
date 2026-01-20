"""
Feature Fusion Layer for Multi-Layer Feature Extraction.

This module provides comprehensive feature extraction from:
- URL structure (length, entropy, special characters)
- Request metadata (headers, payload size)
- Endpoint context (login/admin/public sensitivity)
"""

import math
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional
import numpy as np


class FeatureExtractor:
    """Multi-layer feature extraction with unified feature vector output."""
    
    # Endpoint sensitivity patterns
    SENSITIVE_ENDPOINTS = {
        'admin': ['admin', 'administrator', 'manage', 'control', 'backend', 'dashboard'],
        'auth': ['login', 'signin', 'auth', 'oauth', 'password', 'reset', 'register', 'signup', 'logout'],
        'api': ['api', 'graphql', 'rest', 'webhook', 'v1', 'v2', 'v3'],
        'data': ['export', 'download', 'backup', 'database', 'dump', 'import', 'upload'],
    }
    
    # Special character sets for detection
    SPECIAL_CHARS = set('@#$%^&*()+=[]{}|\\<>?`~')
    SQL_CHARS = set("'\"=-;")
    XSS_CHARS = set('<>()/\\')
    
    # Feature names for the unified vector
    URL_FEATURE_NAMES = [
        'url_length', 'path_length', 'query_length', 'path_depth',
        'param_count', 'url_entropy', 'special_char_count', 'special_char_ratio',
        'sql_char_count', 'xss_char_count', 'digit_ratio', 'uppercase_ratio',
        'has_encoded_chars', 'double_slash_count', 'dot_count'
    ]
    
    METADATA_FEATURE_NAMES = [
        'header_count', 'payload_size', 'has_content_type', 'has_user_agent'
    ]
    
    ENDPOINT_FEATURE_NAMES = [
        'is_admin', 'is_auth', 'is_api', 'is_data', 'sensitivity_score'
    ]
    
    def __init__(self):
        """Initialize the feature extractor."""
        self.all_feature_names = (
            self.URL_FEATURE_NAMES + 
            self.METADATA_FEATURE_NAMES + 
            self.ENDPOINT_FEATURE_NAMES
        )
    
    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
    
    def extract_url_features(self, url: str) -> Dict[str, float]:
        """
        Extract URL structure features.
        
        Features extracted:
        - Length metrics (URL, path, query)
        - Entropy (randomness indicator)
        - Special character counts and ratios
        - SQL/XSS character indicators
        
        Args:
            url: The URL string to analyze
            
        Returns:
            Dictionary of URL features
        """
        parsed = urlparse(url)
        path = parsed.path or ''
        query = parsed.query or ''
        
        url_length = len(url)
        
        return {
            'url_length': url_length,
            'path_length': len(path),
            'query_length': len(query),
            'path_depth': path.count('/'),
            'param_count': len(parse_qs(query)),
            'url_entropy': self._calculate_entropy(url),
            'special_char_count': sum(1 for c in url if c in self.SPECIAL_CHARS),
            'special_char_ratio': sum(1 for c in url if c in self.SPECIAL_CHARS) / max(url_length, 1),
            'sql_char_count': sum(1 for c in url if c in self.SQL_CHARS),
            'xss_char_count': sum(1 for c in url if c in self.XSS_CHARS),
            'digit_ratio': sum(1 for c in url if c.isdigit()) / max(url_length, 1),
            'uppercase_ratio': sum(1 for c in url if c.isupper()) / max(url_length, 1),
            'has_encoded_chars': 1.0 if '%' in url else 0.0,
            'double_slash_count': url.count('//') - 1,  # Subtract 1 for protocol
            'dot_count': url.count('.'),
        }
    
    def extract_metadata_features(self, headers: Optional[Dict[str, str]] = None, 
                                   payload: Optional[bytes] = None) -> Dict[str, float]:
        """
        Extract request metadata features.
        
        Features extracted:
        - Header count
        - Payload size
        - Presence of important headers
        
        Args:
            headers: HTTP headers dictionary
            payload: Request body as bytes
            
        Returns:
            Dictionary of metadata features
        """
        headers = headers or {}
        payload = payload or b''
        
        return {
            'header_count': float(len(headers)),
            'payload_size': float(len(payload)),
            'has_content_type': 1.0 if 'Content-Type' in headers or 'content-type' in headers else 0.0,
            'has_user_agent': 1.0 if 'User-Agent' in headers or 'user-agent' in headers else 0.0,
        }
    
    def extract_endpoint_context(self, url: str) -> Dict[str, float]:
        """
        Classify endpoint sensitivity based on URL patterns.
        
        Sensitivity levels:
        - admin: Administrative endpoints (highest sensitivity)
        - auth: Authentication/authorization endpoints
        - api: API endpoints
        - data: Data export/import endpoints
        - public: Regular public endpoints (lowest sensitivity)
        
        Args:
            url: The URL to classify
            
        Returns:
            Dictionary with endpoint context features
        """
        parsed = urlparse(url)
        path_lower = (parsed.path or '').lower()
        
        is_admin = any(kw in path_lower for kw in self.SENSITIVE_ENDPOINTS['admin'])
        is_auth = any(kw in path_lower for kw in self.SENSITIVE_ENDPOINTS['auth'])
        is_api = any(kw in path_lower for kw in self.SENSITIVE_ENDPOINTS['api'])
        is_data = any(kw in path_lower for kw in self.SENSITIVE_ENDPOINTS['data'])
        
        # Calculate sensitivity score (0-1)
        # admin = 1.0, auth = 0.9, data = 0.8, api = 0.6, public = 0.2
        sensitivity_score = 0.2  # Default for public
        if is_admin:
            sensitivity_score = 1.0
        elif is_auth:
            sensitivity_score = 0.9
        elif is_data:
            sensitivity_score = 0.8
        elif is_api:
            sensitivity_score = 0.6
        
        return {
            'is_admin': 1.0 if is_admin else 0.0,
            'is_auth': 1.0 if is_auth else 0.0,
            'is_api': 1.0 if is_api else 0.0,
            'is_data': 1.0 if is_data else 0.0,
            'sensitivity_score': sensitivity_score,
        }
    
    def get_endpoint_sensitivity_label(self, url: str) -> str:
        """
        Get human-readable sensitivity label for an endpoint.
        
        Args:
            url: The URL to classify
            
        Returns:
            Sensitivity label: 'admin', 'auth', 'api', 'data', or 'public'
        """
        context = self.extract_endpoint_context(url)
        
        if context['is_admin']:
            return 'admin'
        elif context['is_auth']:
            return 'auth'
        elif context['is_data']:
            return 'data'
        elif context['is_api']:
            return 'api'
        else:
            return 'public'
    
    def get_unified_feature_vector(self, url: str, 
                                    headers: Optional[Dict[str, str]] = None,
                                    payload: Optional[bytes] = None) -> np.ndarray:
        """
        Combine all features into a unified feature vector for ML model.
        
        This is the Feature Fusion Layer that combines:
        - URL structure features
        - Request metadata features
        - Endpoint context features
        
        Args:
            url: The URL to analyze
            headers: HTTP headers dictionary
            payload: Request body as bytes
            
        Returns:
            numpy array with all features in consistent order
        """
        url_features = self.extract_url_features(url)
        metadata_features = self.extract_metadata_features(headers, payload)
        endpoint_features = self.extract_endpoint_context(url)
        
        # Combine all features in the correct order
        all_features = {**url_features, **metadata_features, **endpoint_features}
        
        # Create vector in consistent order
        vector = [all_features[name] for name in self.all_feature_names]
        
        return np.array(vector, dtype=np.float32)
    
    def get_feature_dict(self, url: str,
                         headers: Optional[Dict[str, str]] = None,
                         payload: Optional[bytes] = None) -> Dict[str, float]:
        """
        Get all features as a dictionary.
        
        Args:
            url: The URL to analyze
            headers: HTTP headers dictionary
            payload: Request body as bytes
            
        Returns:
            Dictionary with all feature names and values
        """
        url_features = self.extract_url_features(url)
        metadata_features = self.extract_metadata_features(headers, payload)
        endpoint_features = self.extract_endpoint_context(url)
        
        return {**url_features, **metadata_features, **endpoint_features}
