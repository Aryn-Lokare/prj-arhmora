AI Architecture Overview
The project uses a Hybrid Machine Learning Scanner designed to detect malicious URLs (SQL Injection, XSS, etc.) with high precision. It combines Lexical Analysis (NLP) with Behavioral/Statistical Features.

1. Core Model & Libraries
Algorithm: XGBClassifier (XGBoost) - A powerful gradient boosting algorithm known for high performance on structured data.

Feature Extraction: TfidfVectorizer (Scikit-Learn) for text analysis and custom Python functions for numerical features.

Serialization: joblib is used to save/load the trained model (vulnerability_model.pkl) and vectorizer (url_vectorizer.pkl).

2. Feature Engineering
The model uses a "Hybrid" approach by stacking two types of features:

A. Textual Features (TF-IDF)
Analyzes the payload (path + query parameters) of the URL.
Uses Character N-Grams (2-4 chars) to detect patterns like script, %20, UNION, SELECT.
Dimension: Reduced to 8000 max features.

B. Numerical/Statistical Features It extracts 11 heuristic features from each URL:
Length: Total URL length.
Special Char Counts: ., -, /, @, ?, %, &, =, !.
Entropy: A measure of randomness (randomly generated attacks often have high entropy).
Keyword Counts: Specific counts of suspicious words: union, select, script, alert.
Digit Density: Count of numbers in the URL.

3. Training Pipeline
Datasets:
CSIC 2010: A standard dataset for HTTP attacks (SQLi, buffer overflow, etc.).
Malicious Phish (Kaggle): Supplementary dataset for broader coverage.
Balancing: It balances the dataset (50k normal / 50k anomalous) to prevent bias.
Hyperparameters:
n_estimators=300: Number of trees.
max_depth=10: Deep trees to capture complex attack patterns.
learning_rate=0.05: Slower learning for better generalization.

4. Inference Workflow (AIInference Class)
Load: Loads the .pkl files from backend/api/scanner/models/.
Preprocess: Extracts the payload (removes domain) to focus on the attack vector.

Transform: Vectorizes text and calculates numerical stats.
Predict: Returns a probability score (0.0 to 1.0).
> 0.98: High Severity
> 0.90: Medium Severity
> 0.80: Low Severity
< 0.80: Info / Benign

You can run python backend/scripts/benchmark_ai.py to test the model's accuracy on your machine!

