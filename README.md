# Arhmora Project

A full-stack web application with Django backend and Next.js frontend.

## Tech Stack

### Backend
- Django 6.0
- Django REST Framework
- PostgreSQL
- Python Decouple (environment configuration)

### Frontend
- Next.js
- TypeScript
- React

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the `backend` directory with:
   ```
   DB_NAME=arhmora_db
   DB_USER=postgres
   DB_PASSWORD=your_password
   DB_HOST=localhost
   DB_PORT=5432
   SECRET_KEY=your_secret_key
   DEBUG=True
   ```

5. Create PostgreSQL database:
   ```sql
   CREATE DATABASE arhmora_db;
   ```

6. Run migrations:
   ```bash
   python manage.py migrate
   ```

7. Create superuser (optional):
   ```bash
   python manage.py createsuperuser
   ```

8. Start the development server:
   ```bash
   python manage.py runserver
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env.local` file (if needed)

4. Start the development server:
   ```bash
   npm run dev
   ```

## Development

- Backend runs on: http://localhost:8000
- Frontend runs on: http://localhost:3000

## License

This project is private.
