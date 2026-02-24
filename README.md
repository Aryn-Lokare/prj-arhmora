# ARMORA - AI-Powered Web Vulnerability Scanner & Management

ARMORA is a state-of-the-art web security platform that combines traditional vulnerability scanning with AI-powered intelligence. It features automated exploit detection, deterministic multi-signal verification (SQLi/RCE), and professional AI-generated security reports tailored for both technical teams and C-level executives.

## 🚀 Key Features

- **AI-Driven Intelligence** - Automatic triage and explanation of vulnerabilities using Gemini/OpenRouter.
- **Advanced Scanning** - Concurrent detection engine for SQLi, XSS, RCE, LFI, and SSRF.
- **Exploit Verification (Layer 2)** - Deterministic verification system to virtually eliminate false positives.
- **Enterprise Reporting** - Professional PDF reports generated with consulting-grade typography and layout.
- **Full Auth Suite** - JWT-based security, Google OAuth 2.0, and email verification.

## 🛠️ Tech Stack

### Backend

- **Framework**: Django 6.0 + Django REST Framework
- **Database**: PostgreSQL (Relational persistence)
- **Task Queue**: Celery (Background scanning)
- **Broker/Cache**: Redis
- **Security**: Simple JWT (Auth), OWASP-aligned detection logic
- **AI**: OpenAI SDK (via OpenRouter for Gemini 2.0 Flash)

### Frontend

- **Framework**: Next.js 16.1 (App Router)
- **Styling**: Tailwind CSS 4 + Radix UI
- **State/Auth**: React Context + Axios interceptors
- **Icons**: Lucide React / Tabler Icons

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.10+**
- **Node.js 18+**
- **PostgreSQL 14+**
- **Redis Server** (required for scanning)
- **Git**

---

## 🚀 Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/Aryn-Lokare/prj-arhmora.git
cd prj-arhmora
```

### Step 2: Backend Setup

#### 2.1 Create Virtual Environment & Install Dependencies

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

#### 2.2 Configure Infrastructure (PostgreSQL & Redis)

1. **Database**: Create a database named `arhmora_db` in PostgreSQL.
2. **Redis**: Ensure a Redis server is running (default `localhost:6379`).

#### 2.3 Environment Variables

Create a `.env` file in the `backend/` directory:

```env
# Database
DB_NAME=arhmora_db
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

# Django
SECRET_KEY=your_secret_key
DEBUG=True

# AI Intelligence (OpenRouter)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=google/gemini-2.0-flash-001

# Celery & Redis
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Email (Optional - for verification)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

#### 2.4 Initialize Database & Run Server

```bash
python manage.py migrate
python manage.py runserver
```

✅ Backend running at: **http://localhost:8000**

---

### Step 3: Scanning Engine (Celery Setup)

ARMORA requires a running Celery worker to process background scans.

**Open a new terminal**, activate the venv, and run:

**Windows**:

```powershell
celery -A myproject worker --loglevel=info --pool=solo
```

**macOS/Linux**:

```bash
celery -A myproject worker --loglevel=info
```

---

### Step 4: Frontend Setup

**Open a new terminal** in the project root:

```bash
cd frontend
npm install
```

#### 4.1 Configure Frontend Env

Create `.env.local` in the `frontend/` directory:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your_google_id
```

#### 4.2 Start Development Server

```bash
npm run dev
```

✅ Frontend running at: **http://localhost:3000**

---

## 🧪 Testing the Scanner

1. Log in to the dashboard at `http://localhost:3000/dashboard`.
2. Click **"New Scan"**.
3. Enter a target URL (ensure you have permission to scan).
4. Monitor the terminal running the **Celery Worker** to see findings being processed.
5. Once complete, view the **detailed report** and download the **AI-Generated PDF**.

---

## 📁 Project Overview

- `backend/api/scanner/`: Core detection and verification logic.
- `backend/api/scanner/intelligence/`: AI content generation & vulnerability analysis.
- `backend/api/scanner/pdf_renderer.py`: Consulting-grade PDF report engine.
- `frontend/app/(protected)/dashboard/`: Real-time scan management UI.

---

## 👤 Author

**Aryan Lokare**

- GitHub: [@Aryn-Lokare](https://github.com/Aryn-Lokare)

## 📄 License

Private and Proprietary.
