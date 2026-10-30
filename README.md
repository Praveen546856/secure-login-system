# Secure Login System

A security-focused registration and login application built as a cybersecurity internship project. It demonstrates safe password storage, server-side sessions in HTTP-only cookies, CSRF and brute-force protection, SQL-injection-resistant database access, and TOTP two-factor authentication.

> Educational portfolio project for **local development**. See [Limitations](#limitations-and-production-checklist) before deploying anything like it.

## Features
- Registration with validation, duplicate-email/username protection and Argon2id password hashing
- Login with generic error messages, rate limiting and account lockout
- Server-side sessions with an HttpOnly, SameSite cookie, idle + absolute expiry, real logout
- CSRF protection, Origin checks, strict CORS, security headers, request size limit
- TOTP two-factor authentication (works with Google/Microsoft Authenticator, Authy, ...) with recovery codes
- Change password (logs out other devices)
- React dashboard: login, register, overview, profile, security tab, show/hide password, form validation, loading states, notifications, responsive layout

## Technologies
Backend: Python 3.11+, FastAPI, SQLAlchemy 2, SQLite, argon2-cffi, PyOTP, cryptography (Fernet), itsdangerous, Pydantic, Pytest.
Frontend: React, Vite, JavaScript, Axios, React Router, CSS.

## Architecture
```
Browser (React, http://localhost:5174)
   │  /api/*   (same origin; Vite dev server forwards it)
   ▼
FastAPI (http://127.0.0.1:8001)
   ├─ middleware: SecurityHeaders → CORS → RequestGuard (size, Origin, JSON-only)
   ├─ routes/auth.py   register, login, 2FA, logout, password, 2FA setup
   ├─ routes/users.py  dashboard, profile (need a session)
   ├─ auth.py          session lookup, cookie handling, CSRF dependency
   ├─ security.py      Argon2id, tokens, TOTP, encryption
   └─ SQLite (SQLAlchemy ORM): users, sessions, recovery_codes
```
**Why a proxy?** The browser only ever talks to `localhost:5174`. Vite forwards `/api` to the backend, so the session cookie is a normal first-party cookie and can be `SameSite=Strict`. A production setup would do the same with a reverse proxy over HTTPS.

**Login flow:** email+password → (if 2FA on: short-lived signed challenge, then 6-digit code or recovery code) → server creates a random session token, stores only its SHA-256 hash, sends it in an HttpOnly cookie → React keeps only the user info and a CSRF token **in memory**.

## Folder structure
```
secure-login-system/
├── backend/
│   ├── app/
│   │   ├── main.py            app factory, handlers, middleware wiring
│   │   ├── config.py          settings from environment (no default secrets)
│   │   ├── database.py        engine and sessions
│   │   ├── models.py          User, UserSession, RecoveryCode
│   │   ├── schemas.py         Pydantic validation
│   │   ├── security.py        hashing, tokens, TOTP
│   │   ├── auth.py            session + CSRF dependencies
│   │   ├── common_passwords.py
│   │   ├── routes/ (auth.py, users.py)
│   │   └── middleware/ (rate_limit.py, request_guard.py, security_headers.py)
│   ├── scripts/generate_env.py
│   ├── tests/
│   ├── .env.example, requirements.txt, pytest.ini, .gitignore
├── frontend/src/ (components/, pages/, services/, context/, App.jsx, main.jsx, index.css)
├── docs/ (VIVA.md, screenshots/)
└── README.md, .gitignore
```

## Installation (Windows 11, PowerShell, VS Code)
Check your tools (Python 3.11+ and Node 20+):
```powershell
python --version
node --version
```

**Terminal 1: backend**
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m scripts.generate_env
```
`generate_env` creates `backend\.env` with fresh random secrets. **Never commit `.env`** (it is in `.gitignore`).
If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

> Use `python -m pip` / `python -m uvicorn` / `python -m pytest`. On some Windows laptops, security policy blocks the small `.exe` launchers inside the venv, but `python -m` always works.

**Terminal 2: frontend**
```powershell
cd frontend
npm install
```

## Running
Terminal 1:
```powershell
cd backend
.\venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```
Terminal 2:
```powershell
cd frontend
npm run dev
```
Open **http://localhost:5174**. Use `localhost` (not `127.0.0.1`) so the cookie and the proxy are same-origin. These ports differ from the earlier projects (8000/5173), so they can all be running together. API docs (development only): http://127.0.0.1:8001/docs

Try it: Register → Log in → Security tab → Set up 2FA (scan the QR with an authenticator app, save the recovery codes) → Log out → Log in again with a code.

## Configuration (`backend/.env`)
See `.env.example`. Important keys: `SECRET_KEY`, `TOTP_ENCRYPTION_KEY` (the app refuses to start without them), `FRONTEND_ORIGINS`, `COOKIE_SECURE`, `COOKIE_SAMESITE`, session and rate-limit values. With `ENVIRONMENT=production` the app also refuses to start unless `COOKIE_SECURE=true` and all origins are `https://`.

## API documentation
All bodies are JSON. State-changing requests from a logged-in user need the `X-CSRF-Token` header (returned by login and `/api/auth/me`).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | no | health check |
| POST | `/api/auth/register` | no | `{username, email, password}` → 201 user |
| POST | `/api/auth/login` | no | `{email, password}` → user + `csrf_token` and cookie, or `{two_factor_required, challenge}` |
| POST | `/api/auth/login/2fa` | challenge | `{challenge, code}` (6-digit code or recovery code) |
| GET | `/api/auth/me` | session | current user + `csrf_token` |
| POST | `/api/auth/logout` | session + CSRF | deletes the session |
| POST | `/api/auth/change-password` | session + CSRF | `{current_password, new_password}` |
| POST | `/api/auth/2fa/setup` | session + CSRF | `{password}` → `otpauth_uri`, `secret`, `qr_svg_data_uri` |
| POST | `/api/auth/2fa/enable` | session + CSRF | `{code}` → one-time recovery codes |
| POST | `/api/auth/2fa/disable` | session + CSRF | `{password, code}` |
| GET | `/api/users/me` | session | profile |
| GET | `/api/dashboard` | session | account statistics for the logged-in user |

Status codes: `401` not logged in / bad credentials, `403` CSRF or origin failure or wrong confirmation password, `409` duplicate, `413` body too large, `415` not JSON, `422` invalid input (field names and messages only, never the submitted values), `429` rate limited (with `Retry-After`).

## Security features
Each row names where it is implemented and which tests exercise it.

| Feature | Where | Tests |
|---|---|---|
| Argon2id hashing, per-password salt, rehash when parameters change | `security.py` | `test_security_controls.py` (hash tests), `test_registration.py` (hash stored, not plain text) |
| Password policy (length, common list, username/email, digits-only) | `security.py`, `schemas.py` | `test_registration.py` |
| Generic login errors | `routes/auth.py` | `test_login_sessions.py` |
| SQL injection resistance (ORM, bound parameters, validated input) | all queries use SQLAlchemy | `test_security_controls.py` (ORM + endpoint injection tests) |
| Rate limiting: per IP and per account/user, `Retry-After` | `middleware/rate_limit.py`, `routes/auth.py` | `test_security_controls.py`, `test_two_factor.py` |
| Server-side sessions, hashed tokens, absolute + idle expiry | `auth.py`, `models.py` | `test_login_sessions.py` |
| HttpOnly + SameSite cookie, `Secure` configurable | `auth.py` | cookie flag test (HttpOnly, SameSite); `Secure` is configuration-checked only |
| Logout invalidates the session on the server | `routes/auth.py` | `test_login_sessions.py` |
| Session rotation on login; other sessions revoked on password change | `routes/auth.py` | `test_login_sessions.py` |
| CSRF token (HMAC of session) + Origin / Fetch-Metadata check + JSON-only bodies | `auth.py`, `middleware/request_guard.py` | `test_login_sessions.py`, `test_security_controls.py` |
| Strict CORS (only configured origins, credentials) | `main.py` | `test_security_controls.py` |
| Security headers, `no-store` cache control | `middleware/security_headers.py` | `test_security_controls.py` |
| No stack traces or input echo in errors | `main.py` | `test_security_controls.py`, `test_registration.py` |
| Secrets only from environment, startup refuses unsafe config | `config.py` | `test_security_controls.py` |
| TOTP 2FA: encrypted secret (Fernet), replay protection, recovery codes (keyed hashes), rate limited | `security.py`, `routes/auth.py` | `test_two_factor.py` |
| Unknown-email logins take similar time (dummy hash) | `security.py` | **implemented but not covered by an automated test** |

I checked that the tests are meaningful by deliberately breaking six controls one at a time (logout, CSRF check, account lockout, idle timeout, 2FA replay protection, and Argon2id hashing). A test failed each time.

## Testing
```powershell
cd backend
.\venv\Scripts\Activate.ps1
python -m pytest -v
```
Tests use an in-memory database and randomly generated test secrets; they need no internet and never touch your real `.env` or database. Each dot / `PASSED` is a passing test; `FAILED` shows the assertion that broke; the last line shows the totals. Argon2 is deliberately slow, so the suite takes a few seconds.

Frontend checks: `cd frontend; npm run build; npm run lint`.

## Screenshots
Run the app, take your own screenshots (`Win + Shift + S`), save them in `docs/screenshots/` and link them here:
```markdown
![Login](docs/screenshots/login.png)
![Dashboard](docs/screenshots/dashboard.png)
![2FA](docs/screenshots/two-factor.png)
```

## Limitations and production checklist
- **HTTPS is required in production.** Locally the app runs over plain HTTP with `COOKIE_SECURE=false`. In production set `COOKIE_SECURE=true`; the app enforces this.
- Rate-limit counters are **in memory**: they reset on restart and are not shared across several server processes (use Redis in production). Behind a proxy, configure trusted forwarded headers so the client IP is correct.
- Account lockout can be abused to temporarily lock someone out (a known trade-off).
- "Email already exists" on registration reveals that an email is registered. Avoiding this needs email verification, which is not implemented.
- There is no email verification and no password reset by email.
- SQLite and `create_all` are fine for learning; real systems use a server database and migrations (Alembic).
- The body-size limit uses the `Content-Length` header; chunked uploads are not capped by this middleware.
- No audit-log storage, CAPTCHA, or breached-password lookup.
- The common-password list is small and only a teaching aid.
- This project has not had an independent security review or penetration test.

## GitHub
Run git inside the folder that contains `backend`, `frontend` and `README.md`:
```powershell
git init
git add .
git status
```
Check that `.env`, `venv/`, `node_modules/` and `*.db` are **not** listed (`.env.example` should be). Then:
```powershell
git commit -m "Initial commit: Secure Login System with FastAPI, Argon2id, sessions, CSRF protection and TOTP 2FA"
git branch -M main
git remote add origin https://github.com/<your-username>/secure-login-system.git
git push -u origin main
```
Suggested description: *Security-focused login system: FastAPI, SQLAlchemy, Argon2id, HTTP-only sessions, CSRF protection, rate limiting and TOTP 2FA, with a React dashboard.*
If you ever commit a secret by mistake, treat it as leaked: generate new keys and rewrite history.

## Troubleshooting
| Problem | Fix |
|---|---|
| `Startup error: SECRET_KEY is missing` | Run `python -m scripts.generate_env` inside `backend` |
| `Activate.ps1` cannot be loaded | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `pip.exe` / `uvicorn.exe` blocked | Use `python -m pip` and `python -m uvicorn` |
| Page loads but API calls fail | Backend not running on 8001, or you opened `127.0.0.1:5174` instead of `localhost:5174` |
| `Errno 10048` (port in use) | Another program uses the port. Check with `netstat -ano \| findstr :8001` |
| Logged out right after login | Cookie blocked: use `localhost`, keep `COOKIE_SECURE=false` on HTTP |
| "Too many attempts" | Wait for the lockout window (15 minutes) or restart the backend (development only) |
| 2FA code rejected | Phone clock must be correct (automatic time). A code can be used only once |
