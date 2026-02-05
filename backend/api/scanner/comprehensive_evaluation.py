"""
Comprehensive AI Model Evaluation script.
Evaluates both the Multi-Class Classification Model and the URL Attack Model.
Generates metrics and confusion matrices.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

# Add backend directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.insert(0, BACKEND_DIR)

from api.scanner.feature_extractor import FeatureExtractor
from api.scanner.csic_loader import CSICDataLoader

# Paths
# Paths
MODELS_DIR = os.path.join(BASE_DIR, 'models')
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..', '..'))
TRAINING_DATA_DIR = os.path.join(ROOT_DIR, 'data', 'training_data')
TRAINING_DATA_FILE = os.path.join(TRAINING_DATA_DIR, 'training_data.csv')
CSIC_DATA_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data'

# Class labels
CLASS_LABELS = {
    0: 'Normal',
    1: 'SQL Injection',
    2: 'XSS',
    3: 'Path Traversal',
    4: 'Command Injection',
    5: 'Generic Attack'
}

def evaluate_multiclass_model():
    print("\n" + "="*60)
    print("EVALUATION: Multi-Class Vulnerability Classifier")
    print("="*60)
    
    # 1. Load Model
    model_path = os.path.join(MODELS_DIR, 'vulnerability_classifier.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'vulnerability_scaler.pkl')
    metadata_path = os.path.join(MODELS_DIR, 'vulnerability_metadata.pkl')
    
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}")
        return
        
    print(f"Loading model from {model_path}...")
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    # Load feature names from metadata if available
    feature_names = None
    if os.path.exists(metadata_path):
        metadata = joblib.load(metadata_path)
        feature_names = metadata.get('feature_names')
    
    # 2. Load Evaluation Data
    # For now, we will use a reserved part of the synthetic data or regenerate samples
    # If training_data.csv exists, we can use a sample from it (ideally validation set)
    # But since we trained on it, let's generate FRESH samples to test generalization
    
    print("Generating FRESH synthetic samples for evaluation...")
    from api.scanner.synthetic_data_generator import generate_training_data
    
    # Generate smaller set
    samples = generate_training_data() 
    # This generates 8000+ normal and 15*len(payloads) attacks
    # We can use a subset or the whole thing
    
    print(f"Generated {len(samples)} samples.")
    urls = [s[0] for s in samples]
    y_true = np.array([s[1] for s in samples])
    
    # 3. Extract Features
    print("Extracting features...")
    extractor = FeatureExtractor()
    features_list = []
    
    for i, url in enumerate(urls):
        if i % 2000 == 0 and i > 0:
            print(f"  Processed {i}/{len(urls)}...")
        features_list.append(extractor.extract_url_features(url))
        
    df_features = pd.DataFrame(features_list)
    df_features = df_features.fillna(0)
    
    # Ensure columns match
    if feature_names is None:
        feature_names = extractor.URL_FEATURE_NAMES
        
    # Add missing columns
    for col in feature_names:
        if col not in df_features.columns:
            df_features[col] = 0.0
            
    X = df_features[feature_names]
    
    # Scale
    X_scaled = scaler.transform(X)
    
    # 4. Predict
    print("Running predictions...")
    y_pred = model.predict(X_scaled)
    
    # 5. Metrics
    acc = accuracy_score(y_true, y_pred)
    print(f"\nOverall Accuracy: {acc:.4f}")
    
    print("\nClassification Report:")
    target_names = [CLASS_LABELS.get(i, str(i)) for i in range(6)]
    # Filter targets actually present
    present_classes = sorted(list(set(y_true) | set(y_pred)))
    present_names = [CLASS_LABELS.get(i, str(i)) for i in present_classes]
    
    print(classification_report(y_true, y_pred, labels=present_classes, target_names=present_names))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_true, y_pred, labels=present_classes)
    df_cm = pd.DataFrame(cm, index=present_names, columns=present_names)
    print(df_cm)


def evaluate_csic_model():
    print("\n" + "="*60)
    print("EVALUATION: CSIC 2010 URL Attack Model")
    print("="*60)
    
    model_path = os.path.join(MODELS_DIR, 'url_attack_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'url_scaler.pkl')
    
    if not os.path.exists(model_path):
        print("CSIC model not found.")
        return
        
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    # For CSIC, we should load from the actual dataset files if available
    if not os.path.exists(CSIC_DATA_DIR):
        print(f"CSIC data directory {CSIC_DATA_DIR} not found.")
        return
        
    print("Loading CSIC test data...")
    loader = CSICDataLoader(CSIC_DATA_DIR)
    
    # Manually load test files only if possible, but loader.load_data loads all.
    # We'll use load_data for now as defined in previous steps
    try:
        df = loader.load_dataset()
        # Filter for test if possible? logic splits internally? 
        # The loader loads everything into one DF.
        # We'll evaluate on the whole set for now (optimistic) or split if we knew which was which.
        
        print(f"Loaded {len(df)} samples.")
        
        # Features used in training
        URL_FEATURES = [
            'url_length', 'path_length', 'query_length', 'path_depth',
            'param_count', 'url_entropy', 'special_char_count', 'special_char_ratio',
            'sql_char_count', 'xss_char_count', 'digit_ratio', 'uppercase_ratio',
            'has_encoded_chars', 'double_slash_count', 'dot_count',
            'header_count', 'body_length'
        ]
        
        # Prepare X, y
        # We need 'method_encoded' too if the model uses it
        if 'method_encoded' not in df.columns:
            # Need encoder or default
            df['method_encoded'] = 0 
            
        features_to_use = URL_FEATURES + ['method_encoded']
        
        # Check if model expects these features
        # X_test needs to be scaled
        X = df[features_to_use]
        y = df['label']
        
        X_scaled = scaler.transform(X)
        
        y_pred = model.predict(X_scaled)
        
        print(f"Accuracy: {accuracy_score(y, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y, y_pred, target_names=['Normal', 'Attack']))
        
    except Exception as e:
        print(f"Error evaluating CSIC model: {e}")

if __name__ == "__main__":
    evaluate_multiclass_model()
    # evaluate_csic_model() # Optional, uncomment if CSIC data is ready
