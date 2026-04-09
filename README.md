# Secure FastAPI JWT Auth REST API

A production-oriented, security-hardened REST API built with FastAPI, JWT authentication, SQLAlchemy ORM, and CI/CD security controls for a university DevSecOps lab exam.

## Team

Team Name: `Sprint-TeamName` (replace with your actual team name)

## Project Overview

This project provides a secure API for user authentication and per-user item management. It demonstrates defense-in-depth by combining:

- JWT access and refresh token flows
- Password hashing with bcrypt
- Object-level authorization (IDOR prevention)
- CSRF protection for state-changing requests
- Clickjacking and HTTP security headers
- Automated CI/CD checks with testing, SAST, and DAST

## Architecture Diagram (ASCII)

```text
+------------------------+         +------------------------+
|      API Client        |  HTTPS  |      FastAPI App       |
| (Swagger, Postman, UI) +-------->+  Routers + Middleware  |
+------------------------+         +-----------+------------+
                                                |
                                                | SQLAlchemy ORM
                                                v
                                     +------------------------+
                                     |      SQLite DB         |
                                     |  users, items tables   |
                                     +------------------------+

Security Layers:
1) JWT auth dependency on protected routes
2) IDOR ownership checks for /items/{item_id}
3) CSRF token middleware (signed cookie + header)
4) Security headers middleware (anti-clickjacking)
5) CI/CD SAST + DAST security gates
```

## Prerequisites
- Python 3.11+
- Git

## Setup & Run

# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/SecureApp-Sprint-TeamName.git
cd SecureApp-Sprint-TeamName

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
cp .env.example .env
# Edit .env and set: JWT_SECRET_KEY=your-super-secret-key-here

# 5. Run the API
uvicorn app.main:app --reload --port 8000

# 6. Open API docs
# http://localhost:8000/docs   ← Swagger UI
# http://localhost:8000/redoc  ← ReDoc

## Run Tests
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app --cov-report=term-missing

## Run SAST (Bandit)
bandit -r app/ -ll

## Security Features Summary

- IDOR Protection: all item-by-ID routes verify ownership (`item.owner_id == current_user.id`)
- CSRF Protection: state-changing methods require valid `X-CSRF-Token` matched to signed cookie
- Clickjacking Protection: `X-Frame-Options: DENY` and `CSP frame-ancestors 'none'`
- Secure Cookies: `HttpOnly`, `Secure`, and `SameSite=Strict` for refresh and CSRF cookies
- Password Security: bcrypt hashing with cost factor 12
- Secret Management: JWT secret loaded from environment variables only
- Safe Data Access: SQLAlchemy ORM-only queries (no raw SQL)

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci-cd.yml`) executes these gated jobs:

- `lint`: `black --check` and `flake8`
- `test`: `pytest` with coverage fail threshold `< 80%`
- `sast`: Bandit static scan over `app/` with high-severity enforcement
- `dast`: OWASP ZAP baseline scan against a running app instance
- `build`: runs only after all previous jobs pass

The pipeline is configured to fail on critical/high security findings from SAST and DAST gates.
