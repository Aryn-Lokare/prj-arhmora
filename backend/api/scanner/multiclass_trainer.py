"""
Multi-Class Vulnerability Classifier Trainer

Trains an XGBoost model to classify URLs into specific vulnerability types:
    0: Normal (safe)
    1: SQL Injection
    2: XSS (Cross-Site Scripting)
    3: Path Traversal / LFI
    4: Command Injection
    5: Generic Attack / Other

Usage:
    python multiclass_trainer.py
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from feature_extractor import FeatureExtractor

# Paths
# Paths
MODELS_DIR = os.path.join(BASE_DIR, 'models')
TRAINING_DATA_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data\training_data'
TRAINING_DATA_FILE = os.path.join(TRAINING_DATA_DIR, 'training_data.csv')

# Class labels
CLASS_LABELS = {
    0: 'Normal',
    1: 'SQL Injection',
    2: 'XSS',
    3: 'Path Traversal',
    4: 'Command Injection',
    5: 'Generic Attack'
}


def load_training_data():
    """Load training data from CSV file."""
    if not os.path.exists(TRAINING_DATA_FILE):
        print(f"Training data not found at {TRAINING_DATA_FILE}")
        print("Please run synthetic_data_generator.py first.")
        return None, None
    
    print(f"Loading training data from {TRAINING_DATA_FILE}...")
    df = pd.read_csv(TRAINING_DATA_FILE)
    
    return df['url'].tolist(), df['label'].tolist()


def extract_features(urls, extractor):
    """Extract features for all URLs."""
    print(f"Extracting features for {len(urls)} samples...")
    
    features_list = []
    for i, url in enumerate(urls):
        if i % 5000 == 0 and i > 0:
            print(f"  Processed {i}/{len(urls)}...")
        
        try:
            features = extractor.extract_url_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"  Error extracting features for URL: {url[:50]}... - {e}")
            # Add default features on error
            features_list.append({name: 0.0 for name in extractor.URL_FEATURE_NAMES})
    
    return pd.DataFrame(features_list)


def train_multiclass_model():
    """Train the multi-class vulnerability classifier."""
    print("=" * 60)
    print("MULTI-CLASS VULNERABILITY CLASSIFIER TRAINER")
    print("=" * 60)
    
    # 1. Load Data
    urls, labels = load_training_data()
    if urls is None:
        return
    
    print(f"Loaded {len(urls)} samples")
    
    # Print class distribution
    label_counts = pd.Series(labels).value_counts().sort_index()
    print("\nClass distribution:")
    for label, count in label_counts.items():
        print(f"  {label} ({CLASS_LABELS[label]}): {count}")
    
    # 2. Extract Features
    extractor = FeatureExtractor()
    df_features = extract_features(urls, extractor)
    
    # Fill NaN values
    df_features = df_features.fillna(0)
    
    # Get feature columns (should match URL_FEATURE_NAMES)
    feature_columns = extractor.URL_FEATURE_NAMES
    
    # Ensure all features exist
    for col in feature_columns:
        if col not in df_features.columns:
            df_features[col] = 0.0
    
    X = df_features[feature_columns]
    y = np.array(labels)
    
    print(f"\nFeature set ({len(feature_columns)} features): {feature_columns}")
    
    # 3. Scale Features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 4. Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
    
    # 5. Train XGBoost Multi-Class Classifier
    print("\nTraining XGBoost multi-class classifier...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        objective='multi:softprob',  # Multi-class probability output
        num_class=6,
        eval_metric='mlogloss',
        n_jobs=-1,
        random_state=42,
        use_label_encoder=False
    )
    
    model.fit(X_train, y_train)
    
    # 6. Evaluate
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    
    # Classification report
    print("\nClassification Report:")
    target_names = [CLASS_LABELS[i] for i in range(6)]
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(pd.DataFrame(cm, 
                       index=[f"True {CLASS_LABELS[i]}" for i in range(6)],
                       columns=[f"Pred {CLASS_LABELS[i][:4]}" for i in range(6)]))
    
    # Feature importance
    print("\nTop 10 Feature Importances:")
    importance = pd.Series(model.feature_importances_, index=feature_columns)
    for feat, imp in importance.nlargest(10).items():
        print(f"  {feat}: {imp:.4f}")
    
    # 7. Save Artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    model_path = os.path.join(MODELS_DIR, 'vulnerability_classifier.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'vulnerability_scaler.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    # Save class labels and feature names for inference
    metadata = {
        'class_labels': CLASS_LABELS,
        'feature_names': feature_columns,
        'accuracy': accuracy
    }
    metadata_path = os.path.join(MODELS_DIR, 'vulnerability_metadata.pkl')
    joblib.dump(metadata, metadata_path)
    
    print("\n" + "=" * 60)
    print("MODEL SAVED")
    print("=" * 60)
    print(f"Model: {model_path}")
    print(f"Scaler: {scaler_path}")
    print(f"Metadata: {metadata_path}")
    print("\nTraining complete!")
    
    return model, scaler, accuracy


def test_model():
    """Quick test of the trained model."""
    print("\n" + "=" * 60)
    print("TESTING MODEL WITH SAMPLE URLS")
    print("=" * 60)
    
    # Load model
    model_path = os.path.join(MODELS_DIR, 'vulnerability_classifier.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'vulnerability_scaler.pkl')
    
    if not os.path.exists(model_path):
        print("Model not found. Please train first.")
        return
    
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    extractor = FeatureExtractor()
    
    # Test URLs
    test_urls = [
        # Normal
        "https://example.com/products?page=1",
        "https://shop.example.com/category/electronics",
        # SQLi
        "https://example.com/search?q=' OR '1'='1",
        "https://example.com/user?id=1 UNION SELECT * FROM users",
        # XSS
        "https://example.com/page?input=<script>alert(1)</script>",
        "https://example.com/view?data=<img src=x onerror=alert(1)>",
        # Path Traversal
        "https://example.com/file?path=../../../etc/passwd",
        "https://example.com/download?doc=....//....//etc/shadow",
        # Command Injection
        "https://example.com/ping?host=127.0.0.1; cat /etc/passwd",
        "https://example.com/exec?cmd=test | whoami",
    ]
    
    for url in test_urls:
        features = extractor.extract_url_features(url)
        X = pd.DataFrame([features])[extractor.URL_FEATURE_NAMES].fillna(0)
        X_scaled = scaler.transform(X)
        
        probs = model.predict_proba(X_scaled)[0]
        predicted_class = np.argmax(probs)
        confidence = probs[predicted_class]
        
        print(f"\nURL: {url[:60]}...")
        print(f"  Prediction: {CLASS_LABELS[predicted_class]} ({confidence:.1%})")
        print(f"  Probabilities: ", end="")
        for i, p in enumerate(probs):
            if p > 0.05:
                print(f"{CLASS_LABELS[i][:4]}:{p:.1%} ", end="")
        print()


if __name__ == "__main__":
    # Train the model
    result = train_multiclass_model()
    
    if result:
        # Test with sample URLs
        test_model()
