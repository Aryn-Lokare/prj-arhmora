import os
import sys
import time
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, recall_score, precision_score
import joblib

# Add backend to path to import scanners/models
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from api.scanner.ai_model import AIInference, load_and_preprocess

def run_benchmark():
    output = []
    def log(msg):
        print(msg)
        output.append(msg)

    log("="*60)
    log(" ARHMORA AI SCANNER PERFORMANCE BENCHMARK")
    log("="*60)
    
    # 1. Load Engine
    log("\n[1/4] Initializing AI Engine...")
    start_time = time.time()
    # Path relative to backend/
    engine = AIInference(model_dir=os.path.join('api', 'scanner'))
    load_time = (time.time() - start_time) * 1000
    
    if not engine.loaded:
        log("❌ Error: AI Model could not be loaded.")
        return

    log(f"✅ Engine Loaded in {load_time:.2f}ms")

    # 2. Dataset Performance
    log("\n[2/4] Evaluating Dataset Accuracy (Sample: 2000 records)...")
    import contextlib
    with contextlib.redirect_stdout(None):
        results = load_and_preprocess()
        # unpack: X_train_s, X_test_s, y_train, y_test, scaler, encoders, test_df
        test_df = results[-1]
    
    test_sample = test_df.sample(min(2000, len(test_df)), random_state=42)
    y_true = test_sample['label'].tolist()
    y_pred_prob = []
    
    start_time = time.time()
    for _, row in test_sample.iterrows():
        # Pass the row as a feature dict
        feature_dict = row.to_dict()
        y_pred_prob.append(engine.predict(feature_dict))
    total_inf_time = (time.time() - start_time) * 1000
    avg_inf_time = total_inf_time / len(test_sample) if not test_sample.empty else 0
    
    y_pred = [1 if p >= 0.5 else 0 for p in y_pred_prob]
    acc = accuracy_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    
    log(f"📊 Accuracy:  {acc:.2%}")
    log(f"🛡️ Recall (Attack Detection): {rec:.2%}")
    log(f"🎯 Precision (Cleanliness): {prec:.2%}")
    log(f"⚡ Average Latency: {avg_inf_time:.2f}ms per record")

    # 3. Payload Stress Test
    log("\n[3/4] Vulnerability Payload Stress Test:")
    payloads = [
        ("SQL Injection", "http://test.com/login?u=' OR 1=1 --"),
        ("XSS Attack", "http://test.com/search?q=<script>alert('XSS')</script>"),
        ("Path Traversal", "http://test.com/view?file=../../etc/passwd"),
        ("Clean URL", "http://test.com/home/dashboard/v1/user")
    ]
    
    for name, url in payloads:
        prob = engine.predict(url)
        severity = engine.calculate_severity(prob)
        status = "✅ CAUGHT" if prob > 0.8 else "❌ MISSED"
        if name == "Clean URL": status = "✅ PASSED" if prob < 0.5 else "⚠️ FALSE POSITIVE"
        log(f"  - {name:15}: Prob: {prob:.4f} | Severity: {severity:6} | {status}")

    # 4. Summary
    log("\n[4/4] Conclusion:")
    if rec > 0.95:
        log("🟢 DETECTION STRENGTH: ELITE (95%+ Attacks Identified)")
    elif rec > 0.85:
        log("🟡 DETECTION STRENGTH: STRONG (85%+ Attacks Identified)")
    else:
        log("🔴 DETECTION STRENGTH: NEEDS IMPROVEMENT")

    log(f"🟢 ENGINE SPEED: {'FAST' if avg_inf_time < 50 else 'MODERATE'} ({avg_inf_time:.1f}ms/req)")
    log("\n" + "="*60)

    # Write to log file for agent retrieval
    with open("benchmark_log.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(output))

if __name__ == "__main__":
    run_benchmark()
