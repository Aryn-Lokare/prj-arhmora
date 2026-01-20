import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..', '..'))
DATA_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data'
TRAIN_PATH = os.path.join(DATA_DIR, 'UNSW_NB15_training-set.csv')
TEST_PATH = os.path.join(DATA_DIR, 'UNSW_NB15_testing-set.csv')

MODEL_PATH = os.path.join(BASE_DIR, 'models', 'nids_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'nids_scaler.pkl')
ENCODERS_PATH = os.path.join(BASE_DIR, 'models', 'nids_encoders.pkl')

# Features to use (subset of most important ones for NIDS)
CATEGORICAL_FEATURES = ['proto', 'service', 'state']
NUMERICAL_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 
    'dmean', 'trans_depth', 'response_body_len'
]

def load_and_preprocess():
    print("Loading UNSW-NB15 dataset...")
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)
    
    # Drop ID and attack_cat (we want binary classification: 0=normal, 1=attack)
    # The label column is 'label'
    
    # Handle categorical encoding
    encoders = {}
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        # Combine train and test to ensure all categories are covered
        combined = pd.concat([train_df[col], test_df[col]]).astype(str)
        le.fit(combined)
        train_df[col] = le.transform(train_df[col].astype(str))
        test_df[col] = le.transform(test_df[col].astype(str))
        encoders[col] = le
        
    # Features and labels
    X_train = train_df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES]
    y_train = train_df['label']
    X_test = test_df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES]
    y_test = test_df['label']
    
    # Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, encoders, test_df

def train_model():
    X_train, X_test, y_train, y_test, scaler, encoders, _ = load_and_preprocess()
    
    print(f"Training on {X_train.shape[0]} samples with {X_train.shape[1]} features...")
    
    model = XGBClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluation
    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save artifacts
    print(f"Saving artifacts to {BASE_DIR}/models/...")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    print("Training complete.")

class AIInference:
    """
    Enhanced AI Inference Engine with confidence scoring and risk calculation.
    
    Features:
    - Probability prediction from XGBoost model
    - Confidence score extraction from prediction margins
    - Risk score calculation (0-100 scale)
    - Confidence-weighted decision logic (block/throttle/allow)
    """
    
    # Configuration thresholds
    BLOCK_CONFIDENCE_THRESHOLD = 0.85
    HIGH_RISK_THRESHOLD = 80
    MEDIUM_RISK_THRESHOLD = 50
    LOW_RISK_THRESHOLD = 20
    
    def __init__(self, model_dir=None):
        if model_dir is None:
            model_dir = os.path.join(BASE_DIR, 'models')
        elif not os.path.exists(os.path.join(model_dir, 'nids_model.pkl')):
            # Check if they are in a 'models' subdirectory of the provided path
            potential_dir = os.path.join(model_dir, 'models')
            if os.path.exists(os.path.join(potential_dir, 'nids_model.pkl')):
                model_dir = potential_dir
        
        self.model_dir = model_dir
        
        # Load NIDS model
        m_path = os.path.join(model_dir, 'nids_model.pkl')
        s_path = os.path.join(model_dir, 'nids_scaler.pkl')
        e_path = os.path.join(model_dir, 'nids_encoders.pkl')
        
        if os.path.exists(m_path) and os.path.exists(s_path) and os.path.exists(e_path):
            self.model = joblib.load(m_path)
            self.scaler = joblib.load(s_path)
            self.encoders = joblib.load(e_path)
            self.loaded = True
        else:
            self.loaded = False
            print(f"Warning: NIDS model artifacts not found in {model_dir}")
        
        # Load URL attack model (CSIC-trained) if available
        url_model_path = os.path.join(model_dir, 'url_attack_model.pkl')
        url_scaler_path = os.path.join(model_dir, 'url_scaler.pkl')
        
        if os.path.exists(url_model_path) and os.path.exists(url_scaler_path):
            self.url_model = joblib.load(url_model_path)
            self.url_scaler = joblib.load(url_scaler_path)
            self.url_model_loaded = True
        else:
            self.url_model = None
            self.url_scaler = None
            self.url_model_loaded = False

    def predict(self, feature_dict):
        """
        Predict probability of attack given a dictionary of features.
        Expected keys in feature_dict: CATEGORICAL_FEATURES + NUMERICAL_FEATURES
        
        Returns:
            float: Attack probability (0.0 to 1.0)
        """
        if not self.loaded:
            return 0.0
            
        try:
            # If a string (like a URL) is passed, we can't easily convert to NIDS features
            # but we can return 0.0 or a dummy value instead of crashing.
            if isinstance(feature_dict, str):
                return 0.0

            # Convert dict to DataFrame to maintain order
            df = pd.DataFrame([feature_dict])
            
            # Encode categorical
            for col, le in self.encoders.items():
                if col in df.columns:
                    # Handle unknown labels by defaulting to the first seen label or 'unknown'
                    try:
                        df[col] = le.transform(df[col].astype(str))
                    except ValueError:
                        df[col] = 0 # Default to 0 if unknown
            
            # Ensure all columns are present
            features = CATEGORICAL_FEATURES + NUMERICAL_FEATURES
            for f in features:
                if f not in df.columns:
                    df[f] = 0
                    
            df = df[features]
            
            # Scale
            X_scaled = self.scaler.transform(df)
            
            # Predict
            prob = self.model.predict_proba(X_scaled)[0][1]
            return float(prob)
        except Exception as e:
            print(f"Prediction error: {e}")
            return 0.0
    
    def predict_with_confidence(self, feature_dict) -> dict:
        """
        Predict attack probability with confidence score and risk score.
        
        Returns:
            dict: {
                'probability': float (0.0-1.0),
                'confidence': float (0.0-1.0),
                'risk_score': int (0-100)
            }
        """
        probability = self.predict(feature_dict)
        
        # Calculate confidence from prediction margin
        # Confidence is highest when probability is near 0 or 1
        confidence = abs(probability - 0.5) * 2  # Maps [0.5-1.0] to [0-1.0]
        
        # Calculate risk score (0-100)
        risk_score = int(probability * 100)
        
        return {
            'probability': probability,
            'confidence': confidence,
            'risk_score': risk_score
        }
    
    def calculate_severity(self, risk_score: int, confidence: float = 1.0) -> str:
        """
        Calculate severity level based on risk score and confidence.
        
        Args:
            risk_score: 0-100 risk score
            confidence: 0.0-1.0 confidence score
            
        Returns:
            Severity level: 'High', 'Medium', 'Low', or 'Info'
        """
        # Apply confidence adjustment to thresholds
        adjusted_score = risk_score * confidence
        
        if adjusted_score >= self.HIGH_RISK_THRESHOLD:
            return "High"
        elif adjusted_score >= self.MEDIUM_RISK_THRESHOLD:
            return "Medium"
        elif adjusted_score >= self.LOW_RISK_THRESHOLD:
            return "Low"
        return "Info"
    
    def should_block(self, risk_score: int, confidence: float) -> bool:
        """
        Determine if a request should be blocked.
        
        Block only if:
        - Risk is High (>= 80) AND
        - Confidence exceeds the threshold (>= 0.85)
        
        Args:
            risk_score: 0-100 risk score
            confidence: 0.0-1.0 confidence score
            
        Returns:
            True if request should be blocked
        """
        return (
            risk_score >= self.HIGH_RISK_THRESHOLD and 
            confidence >= self.BLOCK_CONFIDENCE_THRESHOLD
        )
    
    def get_action(self, risk_score: int, confidence: float) -> str:
        """
        Determine the action to take based on risk and confidence.
        
        Actions:
        - 'block': High risk + high confidence
        - 'throttle': High risk + medium confidence, or medium risk
        - 'allow': Low risk
        - 'flagged': Needs manual review
        
        Args:
            risk_score: 0-100 risk score
            confidence: 0.0-1.0 confidence score
            
        Returns:
            Action string: 'block', 'throttle', 'allow', or 'flagged'
        """
        if self.should_block(risk_score, confidence):
            return 'block'
        elif risk_score >= self.HIGH_RISK_THRESHOLD:
            # High risk but not confident enough to block
            return 'throttle'
        elif risk_score >= self.MEDIUM_RISK_THRESHOLD:
            return 'throttle'
        elif risk_score >= self.LOW_RISK_THRESHOLD:
            return 'flagged'
        else:
            return 'allow'
    
    def analyze_url(self, url: str, headers: dict = None) -> dict:
        """
        Comprehensive URL analysis combining feature extraction and prediction.
        
        This is the main entry point for URL-based attack detection.
        
        Args:
            url: URL to analyze
            headers: Optional HTTP headers dict
            
        Returns:
            dict: Complete analysis result with risk_score, confidence, 
                  severity, action, and endpoint_sensitivity
        """
        from .feature_extractor import FeatureExtractor
        
        extractor = FeatureExtractor()
        
        # Extract features
        url_features = extractor.extract_url_features(url)
        endpoint_sensitivity = extractor.get_endpoint_sensitivity_label(url)
        
        # Get prediction (use URL model if available, otherwise use heuristics)
        if self.url_model_loaded:
            # Use the CSIC-trained URL model
            result = self._predict_url_attack(url, headers)
        else:
            # Use heuristic scoring based on URL features
            result = self._heuristic_url_score(url_features)
        
        # Calculate severity and action
        severity = self.calculate_severity(result['risk_score'], result['confidence'])
        action = self.get_action(result['risk_score'], result['confidence'])
        
        return {
            'probability': result['probability'],
            'confidence': result['confidence'],
            'risk_score': result['risk_score'],
            'severity': severity,
            'action': action,
            'endpoint_sensitivity': endpoint_sensitivity,
        }
    
    def _predict_url_attack(self, url: str, headers: dict = None) -> dict:
        """
        Predict URL attack using CSIC-trained model.
        """
        import math
        from urllib.parse import urlparse, parse_qs
        
        # Extract URL features
        parsed = urlparse(url)
        path = parsed.path or ''
        query = parsed.query or ''
        
        def entropy(s):
            if not s:
                return 0.0
            prob = [s.count(c) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in prob if p > 0)
        
        special_chars = set('@#$%^&*()+=[]{}|\\<>?`~')
        sql_chars = set("'\"=-;")
        xss_chars = set('<>()/\\')
        
        features = {
            'url_length': len(url),
            'path_length': len(path),
            'query_length': len(query),
            'path_depth': path.count('/'),
            'param_count': len(parse_qs(query)),
            'url_entropy': entropy(url),
            'special_char_count': sum(1 for c in url if c in special_chars),
            'special_char_ratio': sum(1 for c in url if c in special_chars) / max(len(url), 1),
            'sql_char_count': sum(1 for c in url if c in sql_chars),
            'xss_char_count': sum(1 for c in url if c in xss_chars),
            'digit_ratio': sum(1 for c in url if c.isdigit()) / max(len(url), 1),
            'uppercase_ratio': sum(1 for c in url if c.isupper()) / max(len(url), 1),
            'has_encoded_chars': 1 if '%' in url else 0,
            'double_slash_count': url.count('//') - 1,
            'dot_count': url.count('.'),
            'header_count': len(headers) if headers else 0,
            'body_length': 0,
            # 'method_encoded': 0, # Not used in current model
        }
        
        try:
            # Create feature vector
            feature_names = [
                'url_length', 'path_length', 'query_length', 'path_depth',
                'param_count', 'url_entropy', 'special_char_count', 'special_char_ratio',
                'sql_char_count', 'xss_char_count', 'digit_ratio', 'uppercase_ratio',
                'has_encoded_chars', 'double_slash_count', 'dot_count',
                'header_count', 'body_length'
            ]
            
            X = pd.DataFrame([features])[feature_names]
            X_scaled = self.url_scaler.transform(X)
            
            prob = self.url_model.predict_proba(X_scaled)[0][1]
            confidence = abs(prob - 0.5) * 2
            risk_score = int(prob * 100)
            
            return {
                'probability': float(prob),
                'confidence': float(confidence),
                'risk_score': risk_score
            }
        except Exception as e:
            print(f"URL prediction error: {e}")
            return self._heuristic_url_score(features)
    
    def _heuristic_url_score(self, url_features: dict) -> dict:
        """
        Calculate heuristic risk score based on URL features.
        Used as fallback when URL model is not available.
        """
        risk_score = 0
        
        # Length-based scoring
        if url_features.get('url_length', 0) > 200:
            risk_score += 15
        elif url_features.get('url_length', 0) > 100:
            risk_score += 5
        
        # Entropy-based scoring
        if url_features.get('url_entropy', 0) > 4.5:
            risk_score += 20
        elif url_features.get('url_entropy', 0) > 4.0:
            risk_score += 10
        
        # Special character scoring
        if url_features.get('special_char_ratio', 0) > 0.1:
            risk_score += 25
        elif url_features.get('special_char_ratio', 0) > 0.05:
            risk_score += 10
        
        # SQL injection indicators
        if url_features.get('sql_char_count', 0) > 3:
            risk_score += 25
        
        # XSS indicators
        if url_features.get('xss_char_count', 0) > 3:
            risk_score += 20
        
        # Encoded characters (potential obfuscation)
        if url_features.get('has_encoded_chars', 0):
            risk_score += 10
        
        risk_score = min(100, risk_score)
        probability = risk_score / 100.0
        confidence = 0.6  # Lower confidence for heuristic scoring
        
        return {
            'probability': probability,
            'confidence': confidence,
            'risk_score': risk_score
        }

if __name__ == "__main__":
    train_model()

