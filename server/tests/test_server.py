import importlib
import os
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient

H = {"X-CET": "1"}
ADMIN_PW = "admin-pass-123"


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("DATA_KEY", "test-key-not-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "Admin")
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PW)
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    import main
    main = importlib.reload(main)
    main._fails.clear()
    return main, db


def client(main, user=None, pw=None):
    c = TestClient(main.app)
    if user:
        r = c.post("/api/login", json={"username": user, "password": pw}, headers=H)
        assert r.status_code == 200, r.text
    return c


def make_user(admin, name, role, pw="user-pass-123"):
    r = admin.post("/api/users", json={"username": name, "name": name.title(), "role": role, "password": pw}, headers=H)
    assert r.status_code == 200, r.text


def test_health_and_page(srv):
    main, _ = srv
    c = client(main)
    h = c.get("/api/health").json()
    assert h["app"] == "cet-payroll" and h["db"] == "sqlite" and h["encrypted"] and h["has_users"]
    r = c.get("/")
    assert r.status_code == 200 and "<title>CET Payroll</title>" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_login_logout_and_bad_password(srv):
    main, _ = srv
    c = client(main)
    assert c.get("/api/me").status_code == 401
    assert c.post("/api/login", json={"username": "admin", "password": "wrong-password"}, headers=H).status_code == 401
    assert c.post("/api/login", json={"username": "ADMIN", "password": ADMIN_PW}, headers=H).status_code == 200
    assert c.get("/api/me").json()["user"]["role"] == "admin"
    c.post("/api/logout", headers=H)
    assert c.get("/api/me").status_code == 401


def test_login_rate_limit(srv):
    main, _ = srv
    c = client(main)
    for _ in range(5):
        assert c.post("/api/login", json={"username": "admin", "password": "nope-nope-nope"}, headers=H).status_code == 401
    assert c.post("/api/login", json={"username": "admin", "password": ADMIN_PW}, headers=H).status_code == 429


def test_writes_need_custom_header(srv):
    main, _ = srv
    c = client(main)
    assert c.post("/api/login", json={"username": "admin", "password": ADMIN_PW}).status_code == 403


def test_shared_state_versions_and_conflict(srv):
    main, _ = srv
    a = client(main, "admin", ADMIN_PW)
    make_user(a, "somchai", "editor")
    b = client(main, "somchai", "user-pass-123")
    assert a.get("/api/state").json() == {"version": 0, "data": None, "updated_by": None, "updated_at": None}
    r = a.put("/api/state", json={"base_version": 0, "data": {"employees": [{"code": "CET001"}], "runs": {}}}, headers=H)
    assert r.json() == {"version": 1}
    got = b.get("/api/state").json()
    assert got["version"] == 1 and got["data"]["employees"][0]["code"] == "CET001" and got["updated_by"] == "admin"
    assert b.put("/api/state", json={"base_version": 1, "data": {"employees": [], "runs": {}}}, headers=H).json() == {"version": 2}
    stale = a.put("/api/state", json={"base_version": 1, "data": {"employees": [1], "runs": {}}}, headers=H)
    assert stale.status_code == 409 and stale.json()["version"] == 2 and stale.json()["updated_by"] == "somchai"
    assert a.get("/api/state/version").json()["version"] == 2


def test_viewer_cannot_save(srv):
    main, _ = srv
    a = client(main, "admin", ADMIN_PW)
    make_user(a, "viewer1", "viewer")
    v = client(main, "viewer1", "user-pass-123")
    assert v.get("/api/state").status_code == 200
    assert v.put("/api/state", json={"base_version": 0, "data": {}}, headers=H).status_code == 403
    assert v.get("/api/users").status_code == 403


def test_data_is_encrypted_at_rest(srv):
    main, db = srv
    a = client(main, "admin", ADMIN_PW)
    a.put("/api/state", json={"base_version": 0, "data": {"employees": [{"name": "Plaintext Marker Somchai"}]}}, headers=H)
    raw = sqlite3.connect(db).execute("select data from state").fetchone()[0]
    assert "Plaintext" not in raw and "Somchai" not in raw
    assert a.get("/api/state").json()["data"]["employees"][0]["name"] == "Plaintext Marker Somchai"


def test_user_admin_rules(srv):
    main, _ = srv
    a = client(main, "admin", ADMIN_PW)
    assert a.post("/api/users", json={"username": "x", "role": "editor", "password": "user-pass-123"}, headers=H).status_code == 400
    assert a.post("/api/users", json={"username": "short", "role": "editor", "password": "123"}, headers=H).status_code == 400
    make_user(a, "nida", "editor")
    assert a.post("/api/users", json={"username": "nida", "role": "editor", "password": "user-pass-123"}, headers=H).status_code == 409
    users = {u["username"]: u for u in a.get("/api/users").json()["users"]}
    me_id = users["admin"]["id"]
    assert a.patch(f"/api/users/{me_id}", json={"role": "editor"}, headers=H).status_code == 400  # last admin
    n = client(main, "nida", "user-pass-123")
    assert a.patch(f"/api/users/{users['nida']['id']}", json={"active": False}, headers=H).status_code == 200
    assert n.get("/api/me").status_code == 401  # deactivated user is logged out
    log = a.get("/api/audit").json()["audit"]
    assert {"user_create", "user_edit"} <= {x["action"] for x in log}


def test_change_password(srv):
    main, _ = srv
    a = client(main, "admin", ADMIN_PW)
    assert a.post("/api/me/password", json={"old": "bad", "new": "new-admin-pass-1"}, headers=H).status_code == 400
    assert a.post("/api/me/password", json={"old": ADMIN_PW, "new": "new-admin-pass-1"}, headers=H).status_code == 200
    assert a.get("/api/me").status_code == 401  # all sessions closed after a password change
    client(main, "admin", "new-admin-pass-1")


def test_admin_reset_from_environment(srv, monkeypatch):
    main, _ = srv
    admin = client(main, "admin", ADMIN_PW)
    make_user(admin, "bob", "viewer")
    # without ADMIN_RESET a changed ADMIN_PASSWORD does nothing once users exist
    monkeypatch.setenv("ADMIN_PASSWORD", "new-admin-pass-1")
    main.bootstrap_admin()
    assert client(main).post("/api/login", json={"username": "admin", "password": "new-admin-pass-1"},
                             headers=H).status_code == 401
    # too short: refused
    monkeypatch.setenv("ADMIN_RESET", "1")
    monkeypatch.setenv("ADMIN_PASSWORD", "short")
    main.bootstrap_admin()
    main._fails.clear()
    client(main, "admin", ADMIN_PW)
    # reset works, old sessions end, other users untouched
    monkeypatch.setenv("ADMIN_PASSWORD", "new-admin-pass-1")
    main.bootstrap_admin()
    assert admin.get("/api/me").status_code == 401
    client(main, "admin", "new-admin-pass-1")
    client(main, "bob", "user-pass-123")
    # a new username creates an extra admin
    monkeypatch.setenv("ADMIN_USERNAME", "AJ2")
    main.bootstrap_admin()
    me = client(main, "aj2", "new-admin-pass-1").get("/api/me").json()
    assert me["user"]["role"] == "admin"
