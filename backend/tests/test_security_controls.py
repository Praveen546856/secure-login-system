import pytest
from sqlalchemy import func, select, text

from app import security
from app.models import User
from tests.conftest import GOOD_PASSWORD, ORIGIN, USER


# ------------------------------------------------------------ password hashing
def test_hash_is_argon2id_and_salted():
    h1, h2 = security.hash_password(GOOD_PASSWORD), security.hash_password(GOOD_PASSWORD)
    assert h1.startswith("$argon2id$")
    assert h1 != h2                      # random salt: same password, different hash
    assert GOOD_PASSWORD not in h1


def test_hash_verification():
    h = security.hash_password(GOOD_PASSWORD)
    assert security.verify_password(h, GOOD_PASSWORD) is True
    assert security.verify_password(h, GOOD_PASSWORD + "x") is False
    assert security.verify_password("not-a-hash", GOOD_PASSWORD) is False


# ------------------------------------------------------------------ SQL injection
INJECTIONS = ["' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "\" OR \"\"=\"", "1; SELECT * FROM users"]


@pytest.mark.parametrize("payload", INJECTIONS)
def test_orm_treats_injection_strings_as_plain_data(app, payload):
    """Even if validation were bypassed, the ORM binds values as parameters."""
    with app.state.session_factory() as db:
        db.add(User(username="real_user", username_lower="real_user", email="real@example.com",
                    password_hash=security.hash_password(GOOD_PASSWORD)))
        db.commit()
        assert db.scalar(select(User).where(User.email == payload)) is None   # no match, no bypass
        assert db.scalar(select(func.count()).select_from(User)) == 1          # table untouched
        # Storing the attack string keeps it as literal text:
        db.add(User(username=payload[:30], username_lower=payload[:30].lower(), email="x@example.com",
                    password_hash="h"))
        db.commit()
        assert db.scalar(select(User.username).where(User.email == "x@example.com")) == payload[:30]
        assert db.scalar(text("SELECT count(*) FROM users")) == 2              # users table still exists


@pytest.mark.parametrize("payload", INJECTIONS)
def test_login_endpoint_resists_injection(client, registered, payload):
    r1 = client.post("/api/auth/login", json={"email": payload, "password": "whatever-123"})
    r2 = client.post("/api/auth/login", json={"email": USER["email"], "password": payload})
    assert r1.status_code in (401, 422) and r2.status_code == 401
    assert "set-cookie" not in r1.headers and "set-cookie" not in r2.headers


@pytest.mark.parametrize("payload", INJECTIONS)
def test_register_endpoint_resists_injection(client, app, payload):
    r = client.post("/api/auth/register", json={"username": payload, "email": "q@example.com",
                                                "password": GOOD_PASSWORD})
    assert r.status_code == 422
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


# ------------------------------------------------------------------ rate limiting
def test_login_rate_limit_per_account(client, registered, settings):
    bad = {"email": USER["email"], "password": "wrong-password-1"}
    for _ in range(settings.login_max_failures):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    blocked = client.post("/api/auth/login", json=bad)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    # Even the CORRECT password is refused while locked out.
    assert client.post("/api/auth/login", json={"email": USER["email"], "password": USER["password"]}).status_code == 429


def test_rate_limit_applies_to_unknown_emails_too(client, settings):
    bad = {"email": "ghost@example.com", "password": "wrong-password-1"}
    codes = [client.post("/api/auth/login", json=bad).status_code for _ in range(settings.login_max_failures + 1)]
    assert codes[-1] == 429  # no difference between real and non-existent accounts


def test_successful_login_resets_failure_counter(client, registered, settings):
    bad = {"email": USER["email"], "password": "wrong-password-1"}
    for _ in range(settings.login_max_failures - 1):
        client.post("/api/auth/login", json=bad)
    assert client.post("/api/auth/login", json={"email": USER["email"], "password": USER["password"]}).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert client.post("/api/auth/login", json=bad).status_code == 401


def test_ip_rate_limit(client, settings):
    codes = [client.post("/api/auth/login", json={"email": f"user{i}@example.com", "password": "x" * 12}).status_code
             for i in range(settings.ip_max_attempts_per_minute + 1)]
    assert 401 in codes and codes[-1] == 429


# ---------------------------------------------------------------- CSRF / headers / CORS
def test_cross_origin_post_blocked(client):
    r = client.post("/api/auth/login", json={"email": "a@example.com", "password": "x" * 12},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_cross_site_fetch_metadata_blocked(client):
    r = client.post("/api/auth/login", json={"email": "a@example.com", "password": "x" * 12},
                    headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_form_content_type_blocked(client):
    r = client.post("/api/auth/login", content="email=a@example.com&password=xxxx",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_oversized_body_blocked(client):
    r = client.post("/api/auth/login", content="x" * 20000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_cors_only_for_frontend_origin(client):
    ok = client.options("/api/auth/login", headers={"Origin": "http://localhost:5174",
                                                    "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5174"
    assert ok.headers.get("access-control-allow-credentials") == "true"
    bad = client.options("/api/auth/login", headers={"Origin": "http://evil.example",
                                                     "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


def test_errors_do_not_leak_internals(app):
    from fastapi.testclient import TestClient

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret internal detail /etc/passwd")

    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500 and "secret" not in r.text and "Traceback" not in r.text


# ------------------------------------------------------------------ configuration
def test_app_refuses_to_start_without_secrets(monkeypatch):
    from app.config import SettingsError, load_settings
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(SettingsError):
        load_settings()


def test_production_requires_secure_cookies(monkeypatch):
    from app.config import SettingsError, load_settings
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    with pytest.raises(SettingsError):
        load_settings()
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("FRONTEND_ORIGINS", "http://insecure.example")
    with pytest.raises(SettingsError):
        load_settings()
