# Arhmora - Full Stack Authentication Application

A production-ready authentication system built with Django REST Framework and Next.js, featuring JWT authentication, Google OAuth, email verification, and password reset functionality.

## 🚀 Features

- **JWT Authentication** - Secure token-based auth with access & refresh tokens
- **Google OAuth 2.0** - One-click social login
- **Email Verification** - Token-based email verification system
- **Password Reset** - Secure password reset flow
- **User Profiles** - Extended profiles with avatars and bio
- **Protected Routes** - Frontend middleware for route protection
- **Token Blacklisting** - Secure logout mechanism

## 🛠️ Tech Stack

### Backend
- Django 6.0
- Django REST Framework 3.16.1
- PostgreSQL
- Simple JWT 5.5.1
- Google Auth Library
- Python Decouple

### Frontend
- Next.js 16.1 (App Router)
- TypeScript
- React 19
- Tailwind CSS 4
- Radix UI Components
- Axios

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.10 or higher** - [Download](https://www.python.org/downloads/)
- **Node.js 18 or higher** - [Download](https://nodejs.org/)
- **PostgreSQL 14 or higher** - [Download](https://www.postgresql.org/download/)
- **Git** - [Download](https://git-scm.com/downloads)

## 🚀 Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/Aryn-Lokare/prj-arhmora.git
cd prj-arhmora
```

### Step 2: Backend Setup

#### 2.1 Create Virtual Environment

```bash
cd backend
python -m venv venv
```

#### 2.2 Activate Virtual Environment

**Windows (PowerShell):**
```powershell
venv\Scripts\activate
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

#### 2.3 Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### 2.4 Create PostgreSQL Database

Open PostgreSQL command line (psql) or pgAdmin and run:

```sql
CREATE DATABASE arhmora_db;
```

#### 2.5 Configure Environment Variables

Create a `.env` file in the `backend` directory:

```bash
touch .env  # macOS/Linux
# OR
New-Item .env  # Windows PowerShell
```

Add the following configuration to `backend/.env`:

```env
# Database Configuration
DB_NAME=arhmora_db
DB_USER=postgres
DB_PASSWORD=your_postgres_password
DB_HOST=localhost
DB_PORT=5432

# Django Configuration
SECRET_KEY=django-insecure-el3@4au@+dr=0ehz)#k%am-#@)^et%@qmk1!^p^)b+&ycgt9-9
DEBUG=True

# Email Configuration (Optional - for email verification)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_password
DEFAULT_FROM_EMAIL=noreply@arhmora.com

# Frontend URL
FRONTEND_URL=http://localhost:3000

# Google OAuth (Optional - for Google login)
GOOGLE_CLIENT_ID=your_google_client_id

# Celery (Optional - for background tasks)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

**Important Notes:**
- Replace `your_postgres_password` with your actual PostgreSQL password
- For email functionality, use Gmail App Password (not your regular password)
- For development, you can use `console.EmailBackend` to print emails to console
- Google OAuth is optional for basic functionality

#### 2.6 Run Database Migrations

```bash
python manage.py migrate
```

You should see output like:
```
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  ...
```

#### 2.7 Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account.

#### 2.8 Start Backend Server

```bash
python manage.py runserver
```

✅ Backend should now be running at: **http://localhost:8000**

Test it by visiting: http://localhost:8000/admin

### Step 3: Frontend Setup

Open a **new terminal window** (keep the backend running).

#### 3.1 Navigate to Frontend Directory

```bash
cd frontend
```

#### 3.2 Install Node Dependencies

```bash
npm install
```

This may take a few minutes.

#### 3.3 Configure Frontend Environment

Create a `.env.local` file in the `frontend` directory:

```bash
touch .env.local  # macOS/Linux
# OR
New-Item .env.local  # Windows PowerShell
```

Add the following configuration to `frontend/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your_google_client_id
```

**Note:** Google Client ID is optional for basic functionality.

#### 3.4 Start Frontend Development Server

```bash
npm run dev
```

✅ Frontend should now be running at: **http://localhost:3000**

## 🎉 You're Ready!

Open your browser and navigate to:
- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000/api
- **Admin Panel:** http://localhost:8000/admin

## 🧪 Testing the Application

### Test Registration
1. Go to http://localhost:3000
2. Click "Sign Up"
3. Fill in the registration form
4. Check your terminal (if using console email backend) for the verification email

### Test Login
1. Go to http://localhost:3000
2. Click "Login"
3. Enter your credentials
4. You should be redirected to the dashboard

## ⚠️ Common Issues & Solutions

### Issue: "ModuleNotFoundError: No module named 'psycopg2'"
**Solution:**
```bash
pip install psycopg2-binary
```

### Issue: "FATAL: password authentication failed for user postgres"
**Solution:**
- Check your PostgreSQL password in the `.env` file
- Ensure PostgreSQL is running: `pg_ctl status`
- Reset password if needed using pgAdmin

### Issue: "FATAL: database 'arhmora_db' does not exist"
**Solution:**
```sql
CREATE DATABASE arhmora_db;
```

### Issue: Frontend shows "Network Error" or "Cannot connect to API"
**Solution:**
- Ensure backend is running on port 8000
- Check `NEXT_PUBLIC_API_URL` in `frontend/.env.local`
- Verify CORS settings in `backend/myproject/settings.py`

### Issue: "Port 3000 is already in use"
**Solution:**
```bash
# Kill process on port 3000
# Windows:
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# macOS/Linux:
lsof -ti:3000 | xargs kill -9
```

### Issue: "Port 8000 is already in use"
**Solution:**
```bash
# Windows:
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# macOS/Linux:
lsof -ti:8000 | xargs kill -9
```

## 📁 Project Structure

```
prj-arhmora/
├── backend/
│   ├── api/                    # Main API app
│   │   ├── models.py          # Database models
│   │   ├── views.py           # API endpoints
│   │   ├── serializers.py     # DRF serializers
│   │   ├── urls.py            # URL routing
│   │   └── utils.py           # Helper functions
│   ├── myproject/             # Django project settings
│   │   ├── settings.py        # Configuration
│   │   └── urls.py            # Root URL config
│   ├── templates/             # Email templates
│   ├── venv/                  # Virtual environment (not in git)
│   ├── .env                   # Environment variables (not in git)
│   ├── manage.py              # Django management
│   └── requirements.txt       # Python dependencies
│
├── frontend/
│   ├── app/                   # Next.js App Router
│   │   ├── (auth)/           # Auth pages (login, signup, etc.)
│   │   ├── (protected)/      # Protected pages (dashboard)
│   │   ├── layout.tsx        # Root layout
│   │   └── page.tsx          # Home page
│   ├── components/            # React components
│   │   ├── auth/             # Auth-related components
│   │   ├── providers/        # Context providers
│   │   └── ui/               # UI components (Radix)
│   ├── lib/                   # Utilities
│   │   ├── api.js            # API client
│   │   └── auth.js           # Auth helpers
│   ├── node_modules/          # Dependencies (not in git)
│   ├── .env.local             # Environment variables (not in git)
│   ├── middleware.js          # Route protection
│   └── package.json           # Node dependencies
│
├── .gitignore
└── README.md
```

## 🔑 API Endpoints

### Authentication
- `POST /api/auth/register/` - Register new user
- `POST /api/auth/login/` - Login
- `POST /api/auth/logout/` - Logout
- `POST /api/auth/refresh/` - Refresh access token
- `POST /api/auth/google/` - Google OAuth login

### User Management
- `GET /api/auth/user/` - Get current user
- `PATCH /api/auth/user/` - Update user profile
- `POST /api/auth/change-password/` - Change password

### Email Verification
- `POST /api/auth/verify-email/` - Verify email with token
- `POST /api/auth/resend-verification/` - Resend verification email

### Password Reset
- `POST /api/auth/forgot-password/` - Request password reset
- `POST /api/auth/validate-reset-token/` - Validate reset token
- `POST /api/auth/reset-password/` - Reset password

### Social Accounts
- `GET /api/auth/social-accounts/` - List connected accounts
- `POST /api/auth/social-accounts/{provider}/disconnect/` - Disconnect account

## 🔐 Environment Variables Reference

### Backend Required Variables
| Variable | Description | Example |
|----------|-------------|----------|
| `DB_NAME` | PostgreSQL database name | `arhmora_db` |
| `DB_USER` | PostgreSQL username | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `your_password` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `SECRET_KEY` | Django secret key | `random_string` |
| `DEBUG` | Debug mode | `True` / `False` |

### Backend Optional Variables
| Variable | Description | Default |
|----------|-------------|----------|
| `EMAIL_BACKEND` | Email backend class | `console.EmailBackend` |
| `EMAIL_HOST` | SMTP server | `smtp.gmail.com` |
| `EMAIL_PORT` | SMTP port | `587` |
| `EMAIL_USE_TLS` | Use TLS | `True` |
| `EMAIL_HOST_USER` | Email username | - |
| `EMAIL_HOST_PASSWORD` | Email password | - |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `FRONTEND_URL` | Frontend URL | `http://localhost:3000` |

### Frontend Variables
| Variable | Description | Example |
|----------|-------------|----------|
| `NEXT_PUBLIC_API_URL` | Backend API URL | `http://localhost:8000/api` |
| `NEXT_PUBLIC_GOOGLE_CLIENT_ID` | Google OAuth client ID | - |

## 📝 Development Workflow

### Making Changes to Backend
1. Activate virtual environment
2. Make your changes
3. Create migrations: `python manage.py makemigrations`
4. Apply migrations: `python manage.py migrate`
5. Test your changes

### Making Changes to Frontend
1. Make your changes
2. The dev server will auto-reload
3. Test in browser

## 🚀 Production Deployment

### Backend (Railway/Heroku/DigitalOcean)
1. Set all environment variables in production
2. Set `DEBUG=False`
3. Configure `ALLOWED_HOSTS`
4. Set up production database
5. Configure static file serving
6. Run migrations

### Frontend (Vercel/Netlify)
1. Connect GitHub repository
2. Set environment variables
3. Deploy

## 📄 License

This project is private and proprietary.

## 👤 Author

**Aryan Lokare**
- GitHub: [@Aryn-Lokare](https://github.com/Aryn-Lokare)

## 🙏 Support

If you encounter any issues not covered in this README, please:
1. Check the [Common Issues](#️-common-issues--solutions) section
2. Verify all prerequisites are installed
3. Ensure all environment variables are correctly set
4. Check that both servers are running without errors
