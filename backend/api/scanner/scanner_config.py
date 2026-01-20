"""
Scanner Configuration Module.

Centralized configuration for the enhanced security scanner architecture.
"""

# =============================================================================
# CONFIDENCE AND RISK THRESHOLDS
# =============================================================================

# Confidence threshold for blocking decisions
# Only block requests if confidence exceeds this value
BLOCK_CONFIDENCE_THRESHOLD = 0.85

# Risk score thresholds (0-100 scale)
HIGH_RISK_THRESHOLD = 80    # Score >= 80 is High risk
MEDIUM_RISK_THRESHOLD = 50  # Score >= 50 is Medium risk
LOW_RISK_THRESHOLD = 20     # Score >= 20 is Low risk (below is Info)

# =============================================================================
# BEHAVIORAL ANALYSIS SETTINGS
# =============================================================================

# Sliding window size for behavioral analysis (in seconds)
SLIDING_WINDOW_SECONDS = 300  # 5 minutes

# Frequency anomaly threshold (requests per minute)
FREQUENCY_ANOMALY_THRESHOLD = 60

# Repetition anomaly threshold (ratio of same-endpoint requests)
REPETITION_ANOMALY_THRESHOLD = 0.7  # 70%

# Burst detection settings
BURST_THRESHOLD = 10  # Max requests within burst window
BURST_WINDOW_SECONDS = 5  # Burst detection window

# =============================================================================
# ENDPOINT SENSITIVITY PATTERNS
# =============================================================================

# Keywords for classifying endpoint sensitivity
SENSITIVE_ENDPOINTS = {
    'admin': [
        'admin', 'administrator', 'manage', 'control', 
        'backend', 'dashboard', 'panel', 'console'
    ],
    'auth': [
        'login', 'signin', 'auth', 'oauth', 'password', 
        'reset', 'register', 'signup', 'logout', 'session',
        'token', 'verify', 'activate'
    ],
    'api': [
        'api', 'graphql', 'rest', 'webhook', 
        'v1', 'v2', 'v3', 'endpoint'
    ],
    'data': [
        'export', 'download', 'backup', 'database', 
        'dump', 'import', 'upload', 'file', 'report'
    ],
}

# Sensitivity scores for endpoint types
ENDPOINT_SENSITIVITY_SCORES = {
    'admin': 1.0,
    'auth': 0.9,
    'data': 0.8,
    'api': 0.6,
    'public': 0.2,
}

# =============================================================================
# AI MODEL SETTINGS
# =============================================================================

# Severity thresholds based on probability
SEVERITY_HIGH_THRESHOLD = 0.95
SEVERITY_MEDIUM_THRESHOLD = 0.80
SEVERITY_LOW_THRESHOLD = 0.50

# Model file names
NIDS_MODEL_FILE = 'nids_model.pkl'
NIDS_SCALER_FILE = 'nids_scaler.pkl'
NIDS_ENCODERS_FILE = 'nids_encoders.pkl'
URL_MODEL_FILE = 'url_attack_model.pkl'
URL_SCALER_FILE = 'url_scaler.pkl'
URL_METHOD_ENCODER_FILE = 'url_method_encoder.pkl'

# =============================================================================
# DECISION ACTIONS
# =============================================================================

# Action types for request handling
ACTION_BLOCK = 'block'
ACTION_THROTTLE = 'throttle'
ACTION_ALLOW = 'allow'
ACTION_FLAGGED = 'flagged'

# Decision logic matrix
# Format: (min_risk_score, min_confidence) -> action
DECISION_MATRIX = {
    # High risk + high confidence = block
    (80, 0.85): ACTION_BLOCK,
    # High risk + medium confidence = throttle
    (80, 0.5): ACTION_THROTTLE,
    # Medium risk = throttle
    (50, 0.0): ACTION_THROTTLE,
    # Low risk = allow
    (0, 0.0): ACTION_ALLOW,
}

# =============================================================================
# FIX PRIORITIZATION SETTINGS
# =============================================================================

# Severity weights for priority calculation
SEVERITY_WEIGHTS = {
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Info': 0,
}

# Estimated fix effort by vulnerability type
FIX_EFFORT_ESTIMATES = {
    'Security Misconfiguration': 1,  # Easy
    'Information Disclosure': 1,
    'Missing Headers': 1,
    'Cryptographic Failure': 2,      # Medium
    'Reflected XSS': 2,
    'XSS': 2,
    'SSRF Risk': 2,
    'AI-Detected Anomaly': 2,
    'SQL Injection': 3,              # Hard
}

DEFAULT_FIX_EFFORT = 2

# =============================================================================
# URL FEATURE EXTRACTION
# =============================================================================

# Features extracted from URLs for the ML model
URL_FEATURES = [
    'url_length', 'path_length', 'query_length', 'path_depth',
    'param_count', 'url_entropy', 'special_char_count', 'special_char_ratio',
    'sql_char_count', 'xss_char_count', 'digit_ratio', 'uppercase_ratio',
    'has_encoded_chars', 'double_slash_count', 'dot_count',
    'header_count', 'body_length'
]
