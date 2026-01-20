import os
import joblib
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler

from feature_extractor import FeatureExtractor
from csic_loader import CSICDataLoader

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, '..', '..', 'models')
DATA_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data'

def train_csic_model():
    print("="*60)
    print("CSIC 2010 URL Attack Model Trainer")
    print("="*60)
    
    # 1. Load Data
    loader = CSICDataLoader(DATA_DIR)
    requests, labels = loader.load_data()
    
    if not requests:
        print("No data found! Please ensure CSIC 2010 dataset files are in:")
        print(os.path.abspath(DATA_DIR))
        return
        
    print(f"Loaded {len(requests)} requests.")
    
    # 2. Extract Features
    print("Extracting features (this may take a while)...")
    extractor = FeatureExtractor()
    features_list = []
    
    for i, req in enumerate(requests):
        if i % 5000 == 0:
            print(f"  Processed {i}/{len(requests)}...")
            
        url_feats = extractor.extract_url_features(req['url'])
        
        # Add a method feature (categorical -> encoded later or just 0/1)
        # For simplicity, we won't encode method yet, feature_extractor focuses on URL
        # We can add 'header_count' etc.
        url_feats['header_count'] = len(req.get('headers', {}))
        url_feats['body_length'] = len(req.get('raw', '').split('\n\n', 1)[-1]) if '\n\n' in req.get('raw', '') else 0
        
        features_list.append(url_feats)
        
    df = pd.DataFrame(features_list)
    
    # 3. Preprocess
    # Fill NaNs
    df.fillna(0, inplace=True)
    
    # Select features
    feature_columns = [col for col in df.columns if col not in ['url']] # URL isn't in there anyway
    
    print(f"Feature set: {feature_columns}")
    
    X = df[feature_columns]
    y = np.array(labels)
    
    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    # 4. Train XGBoost
    print(f"Training XGBoost on {len(X_train)} samples...")
    model = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='logloss',
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))
    
    # 6. Save Artifacts
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR)
        
    model_path = os.path.join(MODELS_DIR, 'url_attack_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'url_scaler.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"Model saved to {model_path}")
    print(f"Scaler saved to {scaler_path}")
    print("Training complete!")

if __name__ == "__main__":
    train_csic_model()
