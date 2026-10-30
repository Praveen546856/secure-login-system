# Viva Preparation: Secure Login System

## 1. Project in one minute
A web app where users register and log in securely. Passwords are hashed with Argon2id; after login the server creates a session stored in the database and gives the browser a random token in an HttpOnly cookie. The app defends against brute force, CSRF and SQL injection, and supports authenticator-app 2FA.

## 2. Architecture
React frontend → `/api` (same origin via the Vite proxy) → FastAPI → SQLAlchemy → SQLite. Middleware adds security headers, CORS, and a request guard. `security.py` holds the crypto, `auth.py` the session/CSRF dependencies.

## 3. Key code to know
- `security.py`: `hash_password`, `verify_password`, `verify_totp` (replay protection), `csrf_token_for`.
- `auth.py`: `current_session` (cookie → hashed lookup → expiry checks), `require_csrf`.
- `routes/auth.py`: `login` (rate limit, generic error, dummy hash), `login_two_factor`, `change_password`.
- `middleware/request_guard.py`: Origin/Fetch-Metadata/JSON/size checks.

## 4. Questions and answers
1. **Why not store passwords as plain text or with SHA-256?** If the database leaks, plain text exposes every user. Fast hashes like SHA-256 can be brute-forced quickly. Argon2id is deliberately slow and memory-hard.
2. **What is Argon2id?** The recommended Argon2 variant. It mixes data-dependent and independent memory access to resist GPU and side-channel attacks.
3. **What is a salt?** A random value per password so identical passwords have different hashes and precomputed (rainbow) tables are useless. argon2-cffi generates it and stores it inside the hash string.
4. **Why a generic login error?** Different messages for "no such user" and "wrong password" would let attackers discover which emails are registered (user enumeration).
5. **What does the dummy hash do?** If the email does not exist we still run one Argon2 verification so response time is similar. (Implemented, but I have not written an automated timing test.)
6. **How do you prevent SQL injection?** SQLAlchemy ORM sends values as bound parameters, never concatenated into SQL. Pydantic also restricts inputs. Tests insert and query strings like `' OR '1'='1` and show they are treated as plain data.
7. **Cookie sessions vs JWT?** I used server-side sessions: they can be revoked instantly (logout, password change), and the cookie holds only a random token. JWTs are harder to revoke before expiry.
8. **Why store only the hash of the session token?** If the database leaks, attackers cannot use the stored values as cookies.
9. **What do HttpOnly, Secure and SameSite do?** HttpOnly hides the cookie from JavaScript (limits XSS theft). Secure sends it only over HTTPS. SameSite stops the browser sending it on cross-site requests (CSRF defence).
10. **Why is `Secure` false locally?** Local development is plain HTTP. In production the app refuses to start unless it is true.
11. **What is CSRF?** A malicious site makes your browser send an authenticated request to our site, because browsers attach cookies automatically.
12. **How do you defend against CSRF?** Layers: SameSite=Strict cookie, Origin/Fetch-Metadata check, JSON-only bodies, and a per-session CSRF token in the `X-CSRF-Token` header that other sites cannot read.
13. **Is the CSRF token stored in the browser?** Only in a JavaScript variable (memory). After a reload it is fetched again from `/api/auth/me`.
14. **How does session expiry work?** Two limits: absolute (8 hours) and idle (30 minutes without activity). Both are checked on every request.
15. **What happens on logout?** The session row is deleted on the server, so even a copied cookie stops working. A test replays the old cookie to prove it.
16. **How does rate limiting work?** A sliding window per IP (all auth requests) and per account/user (failures). After 5 failures, login returns 429 with Retry-After, even with the correct password. Unknown emails are limited the same way.
17. **Limitations of your rate limiter?** In memory: resets on restart and not shared across processes. Lockout can be abused to annoy a user.
18. **How does TOTP work?** Shared secret + the current 30-second time step → HMAC-based 6-digit code (RFC 6238). The server and phone compute the same code independently.
19. **How are 2FA secrets protected?** Encrypted at rest with Fernet using a key from the environment, since the server must be able to read the secret back (unlike passwords).
20. **What is TOTP replay protection?** We remember the last accepted time step per user and reject codes at or before it, so a code cannot be reused.
21. **Why recovery codes?** To avoid permanent lockout if the phone is lost. They are random, shown once, stored only as keyed hashes, and each works once.
22. **Why ask for the password again before enabling/disabling 2FA or changing the password?** A stolen session alone should not be enough to weaken the account.
23. **Why revoke other sessions on password change?** If the old password was compromised, existing attacker sessions must end.
24. **How are secrets managed?** Only from environment variables (`.env`, git-ignored). The app refuses to start if keys are missing. `generate_env.py` creates random ones.
25. **What security headers do you set?** `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, a restrictive CSP for the API, and `Cache-Control: no-store`.
26. **What does CORS do and how did you configure it?** It controls which web origins may call the API from a browser. Only the configured frontend origin is allowed, with credentials.
27. **How do you avoid leaking information in errors?** Custom handlers return only field names and our own messages; unexpected errors return a generic 500 and log only the exception type.
28. **Is the UI route protection enough?** No. `ProtectedRoute` is only convenience; every protected API call is checked on the server.

## 5. Limitations and future work
1. Needs HTTPS in production (and secure proxy configuration).
2. Redis-backed rate limiting and per-device session list.
3. Email verification, password reset, breached-password check.
4. Alembic migrations and a production database.
5. Independent security testing, audit logging, WebAuthn/passkeys.

## 6. Demo script (4 minutes)
1. Show the two terminals (backend 8001, frontend 5174) and `.env.example` (no secrets committed).
2. Register with a weak password: show the rules. Register properly.
3. Log in with a wrong password: generic message. Try 6 wrong logins: lockout.
4. Log in, show the dashboard. In browser DevTools → Application: the session cookie is HttpOnly; local/session storage are empty.
5. Security tab: enable 2FA with an authenticator app, save recovery codes.
6. Log out, log in with a code. Try an old code: rejected.
7. Run `python -m pytest -v` and show the results.
