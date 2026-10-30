import time

import pyotp
from sqlalchemy import select

from app.models import RecoveryCode, User
from tests.conftest import GOOD_PASSWORD, USER, csrf

LOGIN = {"email": USER["email"], "password": USER["password"]}


def setup_2fa(client, token):
    r = client.post("/api/auth/2fa/setup", headers=csrf(token), json={"password": GOOD_PASSWORD})
    assert r.status_code == 200
    return r.json()


def code_at(secret, offset_steps=0):
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


def enable(client, token):
    data = setup_2fa(client, token)
    r = client.post("/api/auth/2fa/enable", headers=csrf(token), json={"code": code_at(data["secret"])})
    assert r.status_code == 200
    return data["secret"], r.json()["recovery_codes"]


def test_setup_returns_authenticator_compatible_uri(logged_in):
    client, token = logged_in
    data = setup_2fa(client, token)
    assert data["otpauth_uri"].startswith("otpauth://totp/")
    assert "issuer=" in data["otpauth_uri"] and data["secret"] in data["otpauth_uri"]
    assert data["qr_svg_data_uri"].startswith("data:image/svg+xml;base64,")


def test_setup_requires_password_and_csrf(logged_in):
    client, token = logged_in
    assert client.post("/api/auth/2fa/setup", headers=csrf(token), json={"password": "wrong-password-1"}).status_code == 403
    assert client.post("/api/auth/2fa/setup", json={"password": GOOD_PASSWORD}).status_code == 403


def test_secret_is_encrypted_in_database(logged_in, app):
    client, token = logged_in
    data = setup_2fa(client, token)
    with app.state.session_factory() as db:
        stored = db.scalar(select(User.totp_secret_encrypted))
        assert stored and data["secret"] not in stored


def test_enable_rejects_wrong_code(logged_in):
    client, token = logged_in
    setup_2fa(client, token)
    r = client.post("/api/auth/2fa/enable", headers=csrf(token), json={"code": "000000"})
    assert r.status_code == 400


def test_login_requires_second_factor(client, registered):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    secret, _ = enable(client, token)
    client.cookies.clear()

    r = client.post("/api/auth/login", json=LOGIN)
    body = r.json()
    assert r.status_code == 200 and body["two_factor_required"] is True and "set-cookie" not in r.headers
    assert client.get("/api/dashboard").status_code == 401  # password alone gives no session

    ok = client.post("/api/auth/login/2fa", json={"challenge": body["challenge"], "code": code_at(secret, 1)})
    assert ok.status_code == 200 and ok.json()["user"]["two_factor_enabled"] is True
    assert client.get("/api/dashboard").status_code == 200


def test_wrong_code_rejected(client, registered):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    enable(client, token)
    client.cookies.clear()
    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    r = client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": "123456"})
    assert r.status_code == 401 and "set-cookie" not in r.headers


def test_totp_code_cannot_be_replayed(client, registered):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    secret, _ = enable(client, token)
    client.cookies.clear()
    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    code = code_at(secret, 1)
    assert client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": code}).status_code == 200
    client.cookies.clear()
    challenge2 = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    assert client.post("/api/auth/login/2fa", json={"challenge": challenge2, "code": code}).status_code == 401


def test_the_code_used_to_enable_cannot_be_reused_to_login(client, registered):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    secret, _ = enable(client, token)  # enable() used the code for the current step
    client.cookies.clear()
    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    assert client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": code_at(secret)}).status_code == 401


def test_invalid_or_tampered_challenge(client, registered):
    r = client.post("/api/auth/login/2fa", json={"challenge": "x" * 40, "code": "123456"})
    assert r.status_code == 401


def test_recovery_code_works_once(client, registered, app):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    _, codes = enable(client, token)
    assert len(codes) == 8
    with app.state.session_factory() as db:
        hashes = [c.code_hash for c in db.scalars(select(RecoveryCode))]
        assert all(code not in hashes for code in codes)  # only hashes are stored
    client.cookies.clear()

    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    assert client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": codes[0]}).status_code == 200
    client.cookies.clear()
    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    assert client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": codes[0]}).status_code == 401


def test_two_factor_attempts_are_rate_limited(client, registered, settings):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    enable(client, token)
    client.cookies.clear()
    challenge = client.post("/api/auth/login", json=LOGIN).json()["challenge"]
    codes = [client.post("/api/auth/login/2fa", json={"challenge": challenge, "code": "000000"}).status_code
             for _ in range(settings.login_max_failures + 1)]
    assert codes[-1] == 429


def test_disable_requires_password_and_code(client, registered):
    token = client.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
    secret, _ = enable(client, token)
    h = csrf(token)
    assert client.post("/api/auth/2fa/disable", headers=h, json={"password": "wrong-password-1", "code": code_at(secret, 1)}).status_code == 403
    assert client.post("/api/auth/2fa/disable", headers=h, json={"password": GOOD_PASSWORD, "code": "000000"}).status_code == 400
    ok = client.post("/api/auth/2fa/disable", headers=h, json={"password": GOOD_PASSWORD, "code": code_at(secret, 1)})
    assert ok.status_code == 200
    client.cookies.clear()
    assert "two_factor_required" not in client.post("/api/auth/login", json=LOGIN).json()
