from sqlalchemy import select, update

from app.models import UserSession, utcnow
from tests.conftest import USER, csrf

LOGIN = {"email": USER["email"], "password": USER["password"]}


def test_successful_login_sets_secure_cookie(client, registered):
    r = client.post("/api/auth/login", json=LOGIN)
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["email"] == USER["email"] and body["csrf_token"]
    cookie = r.headers["set-cookie"].lower()
    assert "session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "session" not in body and "token" not in {k.lower() for k in body}


def test_invalid_password_gives_generic_error(client, registered):
    r = client.post("/api/auth/login", json={**LOGIN, "password": "wrong-password-1"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password."
    assert "set-cookie" not in r.headers


def test_unknown_email_gives_same_error_as_wrong_password(client, registered):
    wrong_pw = client.post("/api/auth/login", json={**LOGIN, "password": "wrong-password-1"})
    unknown = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-password-1"})
    assert unknown.status_code == wrong_pw.status_code == 401
    assert unknown.json() == wrong_pw.json()


def test_unauthorized_dashboard_access(client):
    for path in ("/api/dashboard", "/api/users/me", "/api/auth/me"):
        assert client.get(path).status_code == 401


def test_dashboard_with_session(logged_in):
    client, _ = logged_in
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert data["username"] == USER["username"] and data["active_sessions"] == 1
    assert data["two_factor_enabled"] is False


def test_forged_cookie_rejected(client, registered):
    client.cookies.set("session", "a" * 43)
    assert client.get("/api/dashboard").status_code == 401


def test_logout_invalidates_session(logged_in):
    client, token = logged_in
    stolen_cookie = client.cookies.get("session")
    r = client.post("/api/auth/logout", headers=csrf(token))
    assert r.status_code == 200
    client.cookies.set("session", stolen_cookie)  # replay the old cookie
    assert client.get("/api/dashboard").status_code == 401  # the server deleted the session


def test_logout_requires_csrf_token(logged_in):
    client, token = logged_in
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers=csrf("wrong")).status_code == 403
    assert client.get("/api/dashboard").status_code == 200  # still logged in
    assert client.post("/api/auth/logout", headers=csrf(token)).status_code == 200


def test_session_stored_as_hash_only(logged_in, app):
    client, _ = logged_in
    raw = client.cookies.get("session")
    with app.state.session_factory() as db:
        row = db.scalar(select(UserSession))
        assert row.token_hash != raw and raw not in row.token_hash


def test_absolute_session_expiry(logged_in, app):
    client, _ = logged_in
    with app.state.session_factory() as db:
        db.execute(update(UserSession).values(expires_at=utcnow().replace(year=2000)))
        db.commit()
    assert client.get("/api/dashboard").status_code == 401


def test_idle_timeout(logged_in, app):
    client, _ = logged_in
    with app.state.session_factory() as db:
        db.execute(update(UserSession).values(last_seen_at=utcnow().replace(year=2000)))
        db.commit()
    assert client.get("/api/dashboard").status_code == 401


def test_login_issues_new_session_each_time(client, registered):
    first = client.post("/api/auth/login", json=LOGIN).headers["set-cookie"]
    second = client.post("/api/auth/login", json=LOGIN).headers["set-cookie"]
    assert first.split(";")[0] != second.split(";")[0]


def test_change_password_logs_out_other_sessions(app, settings, registered):
    from fastapi.testclient import TestClient
    from tests.conftest import ORIGIN
    with TestClient(app, headers=ORIGIN) as a, TestClient(app, headers=ORIGIN) as b:
        token_a = a.post("/api/auth/login", json=LOGIN).json()["csrf_token"]
        b.post("/api/auth/login", json=LOGIN)
        r = a.post("/api/auth/change-password", headers=csrf(token_a),
                   json={"current_password": USER["password"], "new_password": "Brand-New-Passw0rd!"})
        assert r.status_code == 200
        assert a.get("/api/dashboard").status_code == 200
        assert b.get("/api/dashboard").status_code == 401
        assert a.post("/api/auth/login", json=LOGIN).status_code == 401  # old password stops working
        assert a.post("/api/auth/login", json={**LOGIN, "password": "Brand-New-Passw0rd!"}).status_code == 200


def test_change_password_needs_correct_current_password(logged_in):
    client, token = logged_in
    r = client.post("/api/auth/change-password", headers=csrf(token),
                    json={"current_password": "wrong-password-1", "new_password": "Brand-New-Passw0rd!"})
    assert r.status_code == 403
