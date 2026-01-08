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
    def __init__(self, model_dir=None):
        if model_dir is None:
            model_dir = os.path.join(BASE_DIR, 'models')
        elif not os.path.exists(os.path.join(model_dir, 'nids_model.pkl')):
            # Check if they are in a 'models' subdirectory of the provided path
            potential_dir = os.path.join(model_dir, 'models')
            if os.path.exists(os.path.join(potential_dir, 'nids_model.pkl')):
                model_dir = potential_dir
            
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
            print(f"Warning: Model artifacts not found in {model_dir}")

    def predict(self, feature_dict):
        """
        Predict probability of attack given a dictionary of features.
        Expected keys in feature_dict: CATEGORICAL_FEATURES + NUMERICAL_FEATURES
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

    def calculate_severity(self, probability):
        if probability > 0.95: return "High"
        if probability > 0.80: return "Medium"
        if probability > 0.50: return "Low"
        return "Info"

if __name__ == "__main__":
    train_model()
