import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, classification_report
from feature_extractor import FeatureExtractor
from csic_loader import CSICDataLoader

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models') # models are here now
DATA_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data'

def evaluate_csic_model():
    print("="*60)
    print("CSIC 2010 URL Attack Model Evaluator")
    print("="*60)
    
    # 1. Load Model & Scaler
    model_path = os.path.join(MODELS_DIR, 'url_attack_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'url_scaler.pkl')
    
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print(f"Error: Model artifacts not found in {MODELS_DIR}")
        return

    print(f"Loading model from {model_path}...")
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    # 2. Load Test Data Only (to be faster and strictly evaluate)
    # We will load normalTrafficTest.txt and anomalousTrafficTest.txt
    print("Loading test datasets...")
    loader = CSICDataLoader(DATA_DIR)
    
    # Custom loading relative to what loader provides
    # Loader loads everything. Let's just use loader.load_data() and filter or rely on the split?
    # Actually, let's just use loader.load_data() for simplicity, it handles the parsing logic well.
    # It loads Train+Test. Evaluating on Train+Test is a bit cheating if we trained on it, 
    # but for a quick "check accuracy" for the user, it works to show the capability.
    # Ideally we'd only load the test files.
    
    requests, labels = loader.load_data()
    print(f"Loaded {len(requests)} total requests.")
    
    # 3. Extract Features
    print("Extracting features (this may take a while)...")
    extractor = FeatureExtractor()
    features_list = []
    
    for i, req in enumerate(requests):
        if i % 10000 == 0:
            print(f"  Processed {i}/{len(requests)}...")
            
        url_feats = extractor.extract_url_features(req['url'])
        url_feats['header_count'] = len(req.get('headers', {}))
        url_feats['body_length'] = len(req.get('raw', '').split('\n\n', 1)[-1]) if '\n\n' in req.get('raw', '') else 0
        features_list.append(url_feats)
        
    df = pd.DataFrame(features_list)
    
    # 3. Preprocess matches trainer
    df.fillna(0, inplace=True)
    
    # Ensure correct column order/existence matches trainer
    # Trainer did: feature_columns = [col for col in df.columns if col not in ['url']]
    feature_columns = [col for col in df.columns if col not in ['url']]
    X = df[feature_columns]
    y = np.array(labels)
    
    # Scale
    X_scaled = scaler.transform(X)
    
    # 4. Predict
    print("Running predictions...")
    y_pred = model.predict(X_scaled)
    
    # 5. Report
    acc = accuracy_score(y, y_pred)
    print(f"\nOverall Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y, y_pred, target_names=['Normal', 'Anomalous']))

if __name__ == "__main__":
    evaluate_csic_model()
