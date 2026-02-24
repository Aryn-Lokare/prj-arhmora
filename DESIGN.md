# Arhmora Design Document

## 1. Overview & Vision

**Arhmora** is a production-ready vulnerability scanner and security posture management platform designed for small to medium-sized enterprises. It combines traditional heuristic scanning with advanced AI-driven anomaly detection to identify, classify, and explain security vulnerabilities in web applications.

### Core Capabilities:

- **Comprehensive Scanning:** Detects OWASP Top 10 vulnerabilities including SQLi, XSS, SSRF, LFI, and RCE.
- **AI-Powered Analysis:** Utilizes XGBoost and NLP models to reduce false positives and identify subtle attack patterns.
- **Automated Triage:** Ranks findings by exploitability and impact to help developers prioritize fixes.
- **AI Explainer:** Leverages Google Gemini to provide human-readable explanations and remediation steps.
- **Hacker's Eye View:** Provides a security simulation to visualize what an attacker sees.

---

## 2. Technical Stack

### Backend

- **Framework:** Django 6.0 + Django REST Framework 3.16.1
- **Task Queue:** Celery with Redis as a message broker for asynchronous scanning.
- **Database:** PostgreSQL for persistent storage of scan results, findings, and user profiles.
- **Security Logic:** Custom Python-based detection engine with parallelized execution.
- **AI Engine:** XGBoost for classification, scikit-learn for anomaly detection, and OpenRouter/Gemini for explanations.

### Frontend

- **Framework:** Next.js 16.1 (App Router)
- **UI Architecture:** React 19 with TypeScript.
- **Styling:** Tailwind CSS 4 + Radix UI components for a premium, modern aesthetic.
- **State Management:** React Context hooks for authentication and application state.

---

## 3. System Architecture

### 3.1 Scanning Pipeline Workflow

1. **Target Input:** User submits a URL via the frontend.
2. **Task Creation:** The backend validates the URL and queues a Celery task.
3. **Crawling Engine:** A hybrid crawler (Heuristic + Playwright) maps the attack surface.
4. **Vulnerability Detection:** Parallelized threads execute multiple detectors (SQLi, XSS, etc.) concurrently.
5. **AI Inference:** The `SmartDetectionEngine` processes the results through the AI models.
6. **Reporting:** The `gemini_explainer` generates the final report with risk scores and fix suggestions.

### 3.2 AI Architecture

The AI layer consists of:

- **Feature Extraction:** `feature_extractor.py` converts HTTP traffic into numerical vectors.
- **Context Validation:** Heuristics to whitelist safe resources (images, CSS) and apply "Risk Ceilings".
- **Multi-Class Classifier:** XGBoost model trained to distinguish between attack types.
- **NIDS Layer:** Network Intrusion Detection patterns.
- **Explainability:** GPT-based generation of remediation advice.

---

## 4. Future Roadmap & Feature Ideas

### 4.1 AI & Detection Enhancements

- [ ] **Continuous Protection:** Learn baseline client traffic patterns using Autoencoders for anomaly detection.
- [ ] **NLP for Error Analysis:** Analyze stack traces and HTML responses to identify hardcoded secrets or sensitive disclosures.
- [ ] **Zero-Day Feeds:** Integrate public threat intelligence (CVE/NVD) for real-time alerts.

### 4.2 User Experience & Impact

- [ ] **1-Click Auto-Fix:** Generate downloadable config files (.htaccess, nginx.conf) or ready-to-paste snippets for common issues.
- [ ] **Security Badge:** Publicly verifiable badge for websites to display their "Arhmora Verified" status.
- [ ] **Compliance Snapshots:** Automated checks for GDPR, PCI-DSS, and HIPAA readiness.
- [ ] **AI Security Chatbot:** Accessible 24/7 assistant to help non-technical users understand their security posture.

---

## 5. Security & Performance Design

1. **Parallelism:** PAYLOAD-level and URL-level concurrency to reduce scan times by up to 80%.
2. **Rate Limiting:** Intelligent throttling to avoid taking down target websites during scans.
3. **Data Protection:** JWT authentication with token blacklisting and secure session management.
