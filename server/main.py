"""CET Payroll server.

Serves the single-page app (../index.html) and keeps ONE shared payroll state for everyone who logs in.
The state is stored encrypted (AES-256-GCM, key from env DATA_KEY) and versioned: a save must name the
version it was based on, so two people can never silently overwrite each other.

Environment:
  DATABASE_URL    postgresql://... (Neon). Without it the server uses SQLite in ./data, which Render wipes on redeploy.
  DATA_KEY        any long random string; the AES key is derived from it. Losing it makes the stored data unreadable.
  ADMIN_USERNAME  first admin, created only while the user table is empty
  ADMIN_PASSWORD
  ADMIN_RESET     set to 1 to reset ADMIN_USERNAME's password to ADMIN_PASSWORD (at least 10 characters) on the
                  next start: the account becomes an active admin, its sessions end and its lockout clears.
                  Remove it again afterwards.
  SESSION_HOURS   login lifetime (default 12)
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import (Boolean, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine,
                        delete, func, insert, select, update)

log = logging.getLogger("cet-payroll")
ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"
ROLES = ("admin", "editor", "viewer")
SESSION_HOURS = float(os.environ.get("SESSION_HOURS", "12") or 12)
MAX_BODY = 20 * 1024 * 1024
COOKIE = "cet_session"

# ---------- database ----------
_raw = "".join(os.environ.get("DATABASE_URL", "").split())
_m = re.search(r"postgres(?:ql)?://[^\s'\"]+", _raw)
if _m:
    DATABASE_URL = _m.group(0).rstrip("'\"")
elif _raw.lower().startswith("sqlite"):
    DATABASE_URL = _raw
else:
    if _raw:
        log.error("DATABASE_URL is not a postgresql:// connection string; falling back to SQLite")
    DATABASE_URL = "sqlite:///./data/cet-payroll.db"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
if DATABASE_URL.startswith("sqlite") and ":memory:" not in DATABASE_URL:
    os.makedirs("data", exist_ok=True)
engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})

md = MetaData()
users = Table("users", md,
              Column("id", Integer, primary_key=True, autoincrement=True),
              Column("username", String(80), unique=True, nullable=False),
              Column("name", String(200), nullable=False, default=""),
              Column("role", String(20), nullable=False, default="viewer"),
              Column("pw_hash", String(300), nullable=False),
              Column("active", Boolean, nullable=False, default=True),
              Column("created_at", DateTime(timezone=True)),
              Column("last_login", DateTime(timezone=True)))
sessions = Table("sessions", md,
                 Column("token_hash", String(64), primary_key=True),
                 Column("user_id", Integer, nullable=False),
                 Column("created_at", DateTime(timezone=True)),
                 Column("expires_at", DateTime(timezone=True)))
state = Table("state", md,
              Column("id", Integer, primary_key=True),
              Column("version", Integer, nullable=False, default=0),
              Column("data", Text),
              Column("updated_by", String(80)),
              Column("updated_at", DateTime(timezone=True)))
audit = Table("audit", md,
              Column("id", Integer, primary_key=True, autoincrement=True),
              Column("at", DateTime(timezone=True)),
              Column("username", String(80)),
              Column("action", String(40)),
              Column("version", Integer),
              Column("detail", Text))
md.create_all(engine)


def now():
    return datetime.now(timezone.utc)


def iso(d):
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.isoformat()


# ---------- encryption of the shared state ----------
_KEY_SRC = os.environ.get("DATA_KEY", "")
if not _KEY_SRC:
    log.error("DATA_KEY is not set: using a temporary key, saved data will be unreadable after a restart")
    _KEY_SRC = secrets.token_hex(32)
_AES = AESGCM(hashlib.sha256(("cet-payroll|" + _KEY_SRC).encode()).digest())


def seal(obj, version):
    nonce = os.urandom(12)
    ct = _AES.encrypt(nonce, json.dumps(obj, ensure_ascii=False).encode(), b"cet-payroll-state:%d" % version)
    return base64.b64encode(nonce + ct).decode()


def unseal(blob, version):
    raw = base64.b64decode(blob)
    return json.loads(_AES.decrypt(raw[:12], raw[12:], b"cet-payroll-state:%d" % version))


# ---------- passwords and sessions ----------
def hash_pw(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def check_pw(pw, stored):
    try:
        _, s, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def tok_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def strong_enough(pw):
    return isinstance(pw, str) and len(pw) >= 10


_fails = {}  # (ip, username) -> [timestamps]


def too_many_fails(key):
    cut = time.time() - 900
    _fails[key] = [t for t in _fails.get(key, []) if t > cut]
    return len(_fails[key]) >= 5


def bootstrap_admin():
    u, p = os.environ.get("ADMIN_USERNAME", "").strip().lower(), os.environ.get("ADMIN_PASSWORD", "")
    reset = os.environ.get("ADMIN_RESET", "").strip().lower() in ("1", "true", "yes")
    with engine.begin() as c:
        has_users = c.execute(select(func.count()).select_from(users)).scalar()
        if has_users and not reset:
            return
        if not (u and p):
            if reset:
                log.error("ADMIN_RESET is set but ADMIN_USERNAME / ADMIN_PASSWORD are empty; nothing reset")
            return
        if reset and not strong_enough(p):
            log.error("ADMIN_RESET: ADMIN_PASSWORD needs at least 10 characters; nothing reset")
            return
        row = c.execute(select(users.c.id).where(users.c.username == u)).first()
        if row:
            c.execute(update(users).where(users.c.id == row[0]).values(pw_hash=hash_pw(p), role="admin", active=True))
            c.execute(delete(sessions).where(sessions.c.user_id == row[0]))
        else:
            c.execute(insert(users).values(username=u, name=u, role="admin", pw_hash=hash_pw(p), active=True,
                                           created_at=now()))
        c.execute(insert(audit).values(at=now(), username=u, action="admin_reset" if has_users else "bootstrap_admin",
                                       detail=""))
        if has_users:
            log.warning("ADMIN_RESET: password reset for %s; remove ADMIN_RESET from the environment", u)


bootstrap_admin()

# ---------- app ----------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("x-cet") != "1":
            return JSONResponse({"error": "missing X-CET header"}, status_code=403)
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"error": "too large"}, status_code=413)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def current_user(request: Request):
    tok = request.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, "not logged in")
    with engine.begin() as c:
        s = c.execute(select(sessions).where(sessions.c.token_hash == tok_hash(tok))).mappings().first()
        if not s:
            raise HTTPException(401, "not logged in")
        exp = s["expires_at"] if s["expires_at"].tzinfo else s["expires_at"].replace(tzinfo=timezone.utc)
        if exp < now():
            c.execute(sessions.delete().where(sessions.c.token_hash == s["token_hash"]))
            raise HTTPException(401, "session expired")
        u = c.execute(select(users).where(users.c.id == s["user_id"])).mappings().first()
    if not u or not u["active"]:
        raise HTTPException(401, "not logged in")
    return dict(u)


def need(*roles):
    def dep(u=Depends(current_user)):
        if u["role"] not in roles:
            raise HTTPException(403, "not allowed")
        return u
    return dep


def public_user(u):
    return {"id": u["id"], "username": u["username"], "name": u["name"], "role": u["role"],
            "active": bool(u["active"]), "last_login": iso(u.get("last_login"))}


@app.get("/api/health")
def health():
    with engine.begin() as c:
        n = c.execute(select(func.count()).select_from(users)).scalar()
    build = hashlib.sha256(INDEX.read_bytes()).hexdigest()[:12] if INDEX.exists() else None
    return {"app": "cet-payroll", "ok": True, "db": engine.dialect.name, "encrypted": bool(os.environ.get("DATA_KEY")),
            "has_users": bool(n), "build": build}


@app.post("/api/login")
async def login(request: Request, response: Response):
    body = await request.json()
    username = str(body.get("username", "")).strip().lower()
    pw = str(body.get("password", ""))
    key = (request.client.host if request.client else "?", username)
    if too_many_fails(key):
        raise HTTPException(429, "too many attempts, try again in 15 minutes")
    with engine.begin() as c:
        u = c.execute(select(users).where(users.c.username == username)).mappings().first()
        if not u or not u["active"] or not check_pw(pw, u["pw_hash"]):
            _fails.setdefault(key, []).append(time.time())
            raise HTTPException(401, "wrong username or password")
        tok = secrets.token_urlsafe(32)
        c.execute(insert(sessions).values(token_hash=tok_hash(tok), user_id=u["id"], created_at=now(),
                                          expires_at=now() + timedelta(hours=SESSION_HOURS)))
        c.execute(update(users).where(users.c.id == u["id"]).values(last_login=now()))
        c.execute(sessions.delete().where(sessions.c.expires_at < now()))
    _fails.pop(key, None)
    response.set_cookie(COOKIE, tok, max_age=int(SESSION_HOURS * 3600), httponly=True, samesite="strict",
                        secure=request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https",
                        path="/")
    return {"user": public_user(dict(u))}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    tok = request.cookies.get(COOKIE)
    if tok:
        with engine.begin() as c:
            c.execute(sessions.delete().where(sessions.c.token_hash == tok_hash(tok)))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(u=Depends(current_user)):
    return {"user": public_user(u)}


@app.post("/api/me/password")
async def change_password(request: Request, u=Depends(current_user)):
    body = await request.json()
    if not check_pw(str(body.get("old", "")), u["pw_hash"]):
        raise HTTPException(400, "current password is wrong")
    if not strong_enough(body.get("new")):
        raise HTTPException(400, "new password needs at least 10 characters")
    with engine.begin() as c:
        c.execute(update(users).where(users.c.id == u["id"]).values(pw_hash=hash_pw(body["new"])))
        c.execute(sessions.delete().where(sessions.c.user_id == u["id"]))
        c.execute(insert(audit).values(at=now(), username=u["username"], action="password", detail=""))
    return {"ok": True}


def _state_row(c):
    return c.execute(select(state).where(state.c.id == 1)).mappings().first()


@app.get("/api/state")
def get_state(u=Depends(current_user)):
    with engine.begin() as c:
        r = _state_row(c)
    if not r or not r["data"]:
        return {"version": 0, "data": None, "updated_by": None, "updated_at": None}
    try:
        data = unseal(r["data"], r["version"])
    except Exception:
        raise HTTPException(500, "stored data cannot be decrypted: DATA_KEY differs from the key used to save it")
    return {"version": r["version"], "data": data, "updated_by": r["updated_by"], "updated_at": iso(r["updated_at"])}


@app.get("/api/state/version")
def get_version(u=Depends(current_user)):
    with engine.begin() as c:
        r = _state_row(c)
    return {"version": r["version"] if r else 0, "updated_by": r["updated_by"] if r else None,
            "updated_at": iso(r["updated_at"]) if r else None}


@app.put("/api/state")
async def put_state(request: Request, u=Depends(need("admin", "editor"))):
    body = await request.json()
    base = body.get("base_version")
    data = body.get("data")
    if not isinstance(base, int) or not isinstance(data, dict):
        raise HTTPException(400, "base_version (int) and data (object) are required")
    with engine.begin() as c:
        r = _state_row(c)
        cur = r["version"] if r else 0
        if base != cur:
            return JSONResponse({"error": "conflict", "version": cur, "updated_by": r["updated_by"] if r else None,
                                 "updated_at": iso(r["updated_at"]) if r else None}, status_code=409)
        nv = cur + 1
        vals = dict(version=nv, data=seal(data, nv), updated_by=u["username"], updated_at=now())
        if r:
            res = c.execute(update(state).where(state.c.id == 1, state.c.version == cur).values(**vals))
            if res.rowcount != 1:
                return JSONResponse({"error": "conflict", "version": cur + 1}, status_code=409)
        else:
            c.execute(insert(state).values(id=1, **vals))
        n_emp = len(data.get("employees") or [])
        n_runs = len(data.get("runs") or {})
        note = body.get("note") if body.get("note") in ("save", "restore", "overwrite") else "save"
        c.execute(insert(audit).values(at=now(), username=u["username"], action=note,
                                       version=nv, detail=json.dumps({"employees": n_emp, "runs": n_runs})))
    return {"version": nv}


# ---------- admin: users and audit ----------
@app.get("/api/users")
def list_users(u=Depends(need("admin"))):
    with engine.begin() as c:
        rows = c.execute(select(users).order_by(users.c.username)).mappings().all()
    return {"users": [public_user(dict(r)) for r in rows]}


def _admins_left(c, excluding_id):
    return c.execute(select(func.count()).select_from(users).where(
        users.c.role == "admin", users.c.active.is_(True), users.c.id != excluding_id)).scalar()


@app.post("/api/users")
async def create_user(request: Request, u=Depends(need("admin"))):
    b = await request.json()
    username = str(b.get("username", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,40}", username):
        raise HTTPException(400, "username: 3-40 characters a-z 0-9 . _ -")
    if b.get("role") not in ROLES:
        raise HTTPException(400, "role must be admin, editor or viewer")
    if not strong_enough(b.get("password")):
        raise HTTPException(400, "password needs at least 10 characters")
    with engine.begin() as c:
        if c.execute(select(users.c.id).where(users.c.username == username)).first():
            raise HTTPException(409, "username already exists")
        c.execute(insert(users).values(username=username, name=str(b.get("name") or username)[:200], role=b["role"],
                                       pw_hash=hash_pw(b["password"]), active=True, created_at=now()))
        c.execute(insert(audit).values(at=now(), username=u["username"], action="user_create",
                                       detail=json.dumps({"user": username, "role": b["role"]})))
    return {"ok": True}


@app.patch("/api/users/{uid}")
async def edit_user(uid: int, request: Request, u=Depends(need("admin"))):
    b = await request.json()
    vals = {}
    if "name" in b:
        vals["name"] = str(b["name"])[:200]
    if "role" in b:
        if b["role"] not in ROLES:
            raise HTTPException(400, "role must be admin, editor or viewer")
        vals["role"] = b["role"]
    if "active" in b:
        vals["active"] = bool(b["active"])
    if "password" in b:
        if not strong_enough(b["password"]):
            raise HTTPException(400, "password needs at least 10 characters")
        vals["pw_hash"] = hash_pw(b["password"])
    with engine.begin() as c:
        t = c.execute(select(users).where(users.c.id == uid)).mappings().first()
        if not t:
            raise HTTPException(404, "no such user")
        losing_admin = t["role"] == "admin" and (vals.get("role", "admin") != "admin" or vals.get("active") is False)
        if losing_admin and not _admins_left(c, uid):
            raise HTTPException(400, "keep at least one active admin")
        if vals:
            c.execute(update(users).where(users.c.id == uid).values(**vals))
        if "password" in b or vals.get("active") is False:
            c.execute(sessions.delete().where(sessions.c.user_id == uid))
        c.execute(insert(audit).values(at=now(), username=u["username"], action="user_edit",
                                       detail=json.dumps({"user": t["username"], **{k: v for k, v in vals.items()
                                                                                    if k != "pw_hash"},
                                                          "password_reset": "password" in b})))
    return {"ok": True}


@app.get("/api/audit")
def get_audit(limit: int = 100, u=Depends(need("admin"))):
    with engine.begin() as c:
        rows = c.execute(select(audit).order_by(audit.c.id.desc()).limit(max(1, min(limit, 500)))).mappings().all()
    return {"audit": [{**dict(r), "at": iso(r["at"])} for r in rows]}


# ---------- the app page ----------
@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
def page():
    return HTMLResponse(INDEX.read_text(encoding="utf-8"), headers={"Cache-Control": "no-cache"})
