import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import re

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..', '..'))
CSIC_PATH = os.path.join(ROOT_DIR, 'data', 'csic_database.csv')
KAGGE_URL_PATH = os.path.join(ROOT_DIR, 'data', 'malicious_phish.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'vulnerability_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'models', 'url_vectorizer.pkl')

from scipy.sparse import hstack

import math

def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def extract_numerical_features(url_list):
    """Extract a list of numerical features for a list of URLs."""
    features = []
    for url in url_list:
        url = str(url)
        features.append([
            len(url),
            url.count('.'),
            url.count('-'),
            url.count('/'),
            sum(c.isdigit() for c in url),
            len(re.findall(r'[@?%&=!]', url)),
            calculate_entropy(url),
            url.lower().count('union'),
            url.lower().count('select'),
            url.lower().count('script'),
            url.lower().count('alert')
        ])
    return np.array(features)

def load_and_preprocess():
    print("Loading CSIC 2010 dataset...")
    df = pd.read_csv(CSIC_PATH)
    df.columns = df.columns.str.strip()
    
    class_col = next((c for c in df.columns if c.lower() == 'classification'), None)
    url_col = next((c for c in df.columns if c.lower() == 'url'), None)
    
    df = df[[url_col, class_col]].dropna()
    df['label'] = df[class_col].apply(lambda x: 1 if str(x).strip() == '1' else 0)
    
    def get_payload(url):
        if '?' in url:
            return url.split('?', 1)[1]
        return url
        
    df['payload'] = df[url_col].apply(get_payload)
    
    # Increase samples for better accuracy
    normal_df = df[df['label'] == 0]
    anomalous_df = df[df['label'] == 1]
    
    n_samples = min(len(normal_df), len(anomalous_df), 50000)
    data = pd.concat([
        normal_df.sample(n_samples, random_state=42),
        anomalous_df.sample(n_samples, random_state=42)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    return data.rename(columns={'payload': 'url'})

def train_model():
    data = load_and_preprocess()
    
    print("Vectorizing URLs...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=8000)
    X_tfidf = vectorizer.fit_transform(data['url'])
    
    print("Extracting numerical features...")
    X_numerical = extract_numerical_features(data['url'])
    
    X = hstack([X_tfidf, X_numerical])
    y = data['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training XGBoost Classifier (High sensitivity tuning)...")
    # Higher depth and more estimators to capture complex text patterns
    model = XGBClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=10,
        min_child_weight=1,
        subsample=0.9,
        colsample_bytree=0.9,
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
    
    # Save
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("Model training complete.")

class AIInference:
    def __init__(self, model_dir=None):
        if model_dir is None:
            model_dir = BASE_DIR
            
        m_path = os.path.join(model_dir, 'models', os.path.basename(MODEL_PATH))
        v_path = os.path.join(model_dir, 'models', os.path.basename(VECTORIZER_PATH))
        
        if os.path.exists(m_path) and os.path.exists(v_path):
            self.model = joblib.load(m_path)
            self.vectorizer = joblib.load(v_path)
            self.loaded = True
        else:
            self.loaded = False

    def predict(self, url):
        if not self.loaded:
            return 0  # Default to benign if not loaded
        
        # Extract payload (query or path) consistent with training
        payload = url.split('?', 1)[1] if '?' in url else url
        
        # Feature 1: TF-IDF
        X_tfidf = self.vectorizer.transform([payload])
        
        # Feature 2: Numerical
        X_numerical = extract_numerical_features([payload])
        
        # Combine
        X = hstack([X_tfidf, X_numerical])
        
        prob = self.model.predict_proba(X)[0][1] # Probability of being malicious
        return float(prob)

    def calculate_severity(self, probability):
        """Map prediction probability to severity levels."""
        if probability > 0.98:
            return "High"
        elif probability > 0.90:
            return "Medium"
        elif probability >= 0.80:
            return "Low"
        return "Info"

if __name__ == "__main__":
    train_model()
