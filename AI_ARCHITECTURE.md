# Arhmora AI Scanner Architecture

## Overview

Arhmora utilizes a multi-layered, hybrid AI architecture designed to detect web vulnerabilities with high accuracy and explainability. Unlike traditional black-box DL models, Arhmora combines heuristic baselines, statistical anomaly detection, and explainable machine learning (XGBoost) to provide actionable security insights.

## Core Components

### 1. Feature Extraction Layer

**File:** `backend/api/scanner/feature_extractor.py`

- **Purpose:** Transforms raw URLs and HTTP traffic into numerical feature vectors.
- **Features Extracted:**
  - **Structural:** Pattern counts (SQL keywords, script tags), URL entropy, length distribution.
  - **Contextual:** Endpoint sensitivity classification (Auth, Admin, API).
  - **Statistical:** Character ratios, special character density.

### 2. Context Validation Layer (Pre-AI)

**File:** `backend/api/scanner/ai_model.py` (`_validate_context`)

- **Purpose:** Reduces false positives by identifying inherently safe contexts before AI processing.
- **Logic:**
  - Whitelists static resources (.css, .png).
  - Applies risk ceilings to base URLs.
  - Ensures AI doesn't over-flag simple navigational requests.

### 3. AI Inference Engine

**File:** `backend/api/scanner/ai_model.py`

- **Model 1: Multi-Class Vulnerability Classifier (XGBoost)**
  - Detects specific attack types: SQLi, XSS, Path Traversal, Command Injection.
  - **Confidence:** Derived from prediction probabilities (margin analysis).
- **Model 2: Binary URL Attack Detector (CSIC 2010)**
  - Baseline anomaly detection trained on standard datasets.
- **Model 3: NIDS (Network Intrusion Detection)**
  - Analyzes network-level traffic patterns (where applicable).

### 4. Risk Scoring & Prioritization

**Files:** `ai_model.py`, `fix_prioritizer.py`, `confidence_engine.py`

- **Risk Score (0-100):** Calculated from model probability and severity.
- **Multi-Factor Confidence:**
  - `Pattern Confidence`: Regex/Signature matches.
  - `Model Confidence`: XGBoost probability margin.
  - `Context Confidence`: Based on endpoint sensitivity.
- **Prioritization:** Findings are ranked (1-10) based on Risk, Confidence, and Fix Effort.

### 5. Explainability Module

**File:** `backend/api/scanner/gemini_explainer.py`

- **Purpose:** Translates technical findings into human-readable reports.
- **Mechanism:**
  - Uses Google Gemini API with strict prompt engineering.
  - **Fallback:** Template-based explanations if API is unreachable (anti-hallucination).

## Testing & Validation

**Location:** `backend/tests/`

- **Unit Tests:** Verify feature extraction and risk math (`test_feature_extractor.py`, `test_ai_inference.py`).
- **Accuracy Tests:** Benchmark against known payloads (`test_known_payloads.py`).
- **Integration Tests:** Verify full pipeline flow (`test_full_scan_pipeline.py`).
- **Performance:** `comprehensive_evaluation.py` generates confusion matrices and F1 scores.

## Key Design Decisions for Viva

1. **Hybrid Approach:** We use Rules + ML. Rules catch the obvious (low FP), ML catches the subtle (low FN).
2. **Explainability:** We don't just say "Malicious". We say "Why" (features) and "How to fix" (Gemini).
3. **Risk Ceiling:** We innovated a context-aware ceiling to prevent "crying wolf" on safe pages.
4. **Efficiency:** Intelligent feature extraction runs in constant time O(1) relative to URL length.

## Future Roadmap

- [ ] Reinforcement Learning for payload mutation.
- [ ] BERT-based sequence modeling for payload analysis.
