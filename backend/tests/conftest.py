"""Test setup. Secrets are generated randomly for each test run; nothing is hard-coded."""
import os
import secrets

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

# Set BEFORE the app is imported so settings load from this fake environment.
os.environ["SECRET_KEY"] = secrets.token_urlsafe(64)
os.environ["TOTP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory database
os.environ["ENVIRONMENT"] = "development"
os.environ["FRONTEND_ORIGINS"] = "http://localhost:5174"

from app.config import load_settings  # noqa: E402
from app.main import create_app  # noqa: E402

ORIGIN = {"Origin": "http://localhost:5174"}
GOOD_PASSWORD = "Tr1cky-Horse-Staple!"
USER = {"username": "alice_test", "email": "alice@example.com", "password": GOOD_PASSWORD}


@pytest.fixture
def settings():
    return load_settings()


@pytest.fixture
def app(settings):
    return create_app(settings)  # fresh in-memory database and fresh rate limiters per test


@pytest.fixture
def client(app):
    with TestClient(app, headers=ORIGIN) as c:
        yield c


@pytest.fixture
def registered(client):
    r = client.post("/api/auth/register", json=USER)
    assert r.status_code == 201
    return USER


@pytest.fixture
def logged_in(client, registered):
    """A client that is logged in. Returns (client, csrf_token)."""
    r = client.post("/api/auth/login", json={"email": USER["email"], "password": USER["password"]})
    assert r.status_code == 200
    return client, r.json()["csrf_token"]


def csrf(token):
    return {"X-CSRF-Token": token}
