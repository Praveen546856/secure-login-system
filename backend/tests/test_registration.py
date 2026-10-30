import pytest
from sqlalchemy import select

from app.models import User
from tests.conftest import USER


def test_successful_registration(client):
    r = client.post("/api/auth/register", json=USER)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == USER["username"] and body["email"] == USER["email"]
    assert "password" not in body and "password_hash" not in body


def test_password_is_not_stored_in_plain_text(client, app):
    client.post("/api/auth/register", json=USER)
    with app.state.session_factory() as db:
        user = db.scalar(select(User))
        assert user.password_hash != USER["password"]
        assert USER["password"] not in user.password_hash
        assert user.password_hash.startswith("$argon2id$")


def test_duplicate_email_rejected(client, registered):
    r = client.post("/api/auth/register", json={**USER, "username": "someone_else"})
    assert r.status_code == 409


def test_duplicate_email_is_case_insensitive(client, registered):
    r = client.post("/api/auth/register", json={**USER, "username": "bob_test", "email": "ALICE@Example.com"})
    assert r.status_code == 409


def test_duplicate_username_rejected(client, registered):
    r = client.post("/api/auth/register", json={**USER, "email": "other@example.com", "username": "ALICE_TEST"})
    assert r.status_code == 409


@pytest.mark.parametrize("field,value", [
    ("username", "ab"), ("username", "has space"), ("username", "bad;name"), ("username", "x" * 31),
    ("email", "not-an-email"), ("email", "a@b"), ("email", ""),
    ("password", "short1!"), ("password", "password123"), ("password", "1234567890123"),
    ("password", "alice_test-Pass9"), ("password", "x" * 129), ("password", "aaaaaaaaaaaa"),
])
def test_invalid_input_rejected(client, field, value):
    r = client.post("/api/auth/register", json={**USER, field: value})
    assert r.status_code == 422
    assert r.json()["detail"] == "Invalid input."


def test_validation_errors_do_not_echo_password(client):
    secret = "NeverEchoThis-12345"
    r = client.post("/api/auth/register", json={**USER, "email": "bad", "password": secret})
    assert secret not in r.text


def test_missing_and_extra_fields_rejected(client):
    assert client.post("/api/auth/register", json={"username": "abc_def"}).status_code == 422
    assert client.post("/api/auth/register", json={**USER, "is_admin": True}).status_code == 422


def test_email_is_stored_lowercase(client, app):
    client.post("/api/auth/register", json={**USER, "email": "MixedCase@Example.COM"})
    with app.state.session_factory() as db:
        assert db.scalar(select(User.email)) == "mixedcase@example.com"
