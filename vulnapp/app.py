"""oedipus-vulnapp: a small multi-tenant SaaS with six planted API bugs.

Each planted bug is matched to exactly one Oedipus check oracle:

  bola             GET  /api/notes/{note_id}   cross-tenant object read
  jwt (weak)       POST /api/login             HS256 signed with a wordlist secret
  jwt (alg=none)   GET  /api/me                unsigned token accepted
  exposure         GET  /api/debug/users       serializes passwords + tokens
  mass_assignment  POST /api/register          honors client-supplied admin:true
  ssrf             POST /api/url-preview       fetches attacker URL, reflects body
  sqli             GET  /api/products/search   raw string-concatenated SQL

Negative "lookalike" routes prove the scanner does NOT cry wolf on safe code:

  GET  /api/products/{id}      parameterized query (safe SQL)
  POST /api/url-preview-safe   egress allowlist (safe fetch)

Set VULNAPP_SAFE=1 to fix every planted bug (the false-positive control build).
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
import jwt as pyjwt
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# --- build mode -----------------------------------------------------------
SAFE = os.getenv("VULNAPP_SAFE", "0") == "1"

# Weak secret in the vulnerable build. It is a line in
# benchmarks/payloads/jwt-secrets.txt, so oedipus' jwt check verifies the
# target's own token signature against it offline. The hardened build swaps in a
# long random secret that is NOT in any wordlist.
WEAK_JWT_SECRET = "changeme"
STRONG_JWT_SECRET = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, per-process
JWT_SECRET = STRONG_JWT_SECRET if SAFE else WEAK_JWT_SECRET
JWT_ALG = "HS256"

# Only these hosts may be fetched by the *safe* URL-preview endpoint (and by the
# vulnerable one when running the hardened build).
FETCH_ALLOWLIST = {"example.com", "www.example.com"}

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
DB_PATH = Path(tempfile.gettempdir()) / f"vulnapp_{os.getpid()}.db"


# --- in-memory tenants / users / notes ------------------------------------
# users keyed by username; each carries a tenant + a cleartext password + api
# token. Two tenants so BOLA has a victim and an attacker.
_USERS: dict[str, dict[str, Any]] = {}
_NOTES: dict[str, dict[str, Any]] = {}


def _seed_state() -> None:
    _USERS.clear()
    _NOTES.clear()
    seed = [
        ("alice", "alice-pw-9f2", "acme", True, "tok_alice_7c1"),
        ("bob", "bob-pw-3a8", "acme", False, "tok_bob_4d2"),
        ("carol", "carol-pw-5e0", "globex", False, "tok_carol_9b7"),
    ]
    for username, password, tenant, admin, token in seed:
        _USERS[username] = {
            "username": username,
            "password": password,
            "email": f"{username}@{tenant}.example",
            "tenant": tenant,
            "admin": admin,
            "token": token,
        }
    # A seeded note owned by tenant "acme" so the app has content on first load.
    _NOTES["welcome"] = {
        "id": "welcome",
        "title": "Welcome",
        "body": "Internal onboarding notes.",
        "secret": "acme-internal-kickoff-doc",
        "owner": "alice",
        "tenant": "acme",
    }


def _seed_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("DROP TABLE IF EXISTS products")
        conn.execute(
            "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)"
        )
        conn.executemany(
            "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
            [
                (1, "Widget", 9.99),
                (2, "Gadget", 19.99),
                (3, "Gizmo", 29.99),
                (4, "Sprocket", 4.50),
            ],
        )
        conn.commit()
    finally:
        conn.close()


# --- JWT helpers ----------------------------------------------------------
def _issue_token(user: dict[str, Any]) -> str:
    payload = {
        "sub": user["username"],
        "tenant": user["tenant"],
        "admin": user["admin"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _decode_token(token: str) -> dict[str, Any]:
    """Return the token's claims or raise HTTPException(401).

    Vulnerable build: decodes WITHOUT verifying the signature, which also means
    an ``alg=none`` (unsigned) token is happily accepted.  Hardened build: pins
    HS256 and verifies the signature, so forged/unsigned tokens are rejected.
    """
    if SAFE:
        try:
            return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except pyjwt.PyJWTError:
            raise HTTPException(status_code=401, detail="invalid token")
    # VULNERABLE: trust the token without checking who signed it.
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="malformed token")


def _current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    claims = _decode_token(authorization.split(" ", 1)[1].strip())
    username = claims.get("sub")
    user = _USERS.get(username)
    if user is None:
        # An alg=none forgery may name a user that doesn't exist; still treat the
        # claims as an authenticated principal so /api/me demonstrates the break.
        return {"username": username, "tenant": claims.get("tenant"),
                "admin": claims.get("admin", False), "forged": True}
    return user


# --- request models -------------------------------------------------------
class RegisterIn(BaseModel):
    username: str
    password: str
    email: str = ""
    # The presence of this client-controllable field is the mass-assignment bug.
    admin: bool = False


class LoginIn(BaseModel):
    username: str
    password: str


class NoteIn(BaseModel):
    id: str
    title: str = ""
    body: str = ""
    secret: str = ""


class UrlIn(BaseModel):
    url: str


# --- app factory ----------------------------------------------------------
def create_app() -> FastAPI:
    _seed_state()
    _seed_db()

    app = FastAPI(
        title="Acme Notes (oedipus-vulnapp)",
        version="0.1.0",
        description="A deliberately vulnerable multi-tenant notes SaaS.",
    )

    # ----- UI (not part of the crawled API surface) -----
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home(request: Request):
        return TEMPLATES.TemplateResponse(
            "index.html",
            {"request": request, "safe": SAFE, "products": _list_products(),
             "notes": list(_NOTES.values())},
        )

    @app.get("/ui/notes", response_class=HTMLResponse, include_in_schema=False)
    def ui_notes(request: Request):
        return TEMPLATES.TemplateResponse(
            "_notes.html", {"request": request, "notes": list(_NOTES.values())}
        )

    # A stand-in for the cloud metadata service (AWS IMDS at 169.254.169.254).
    # Kept OUT of the OpenAPI schema, so it is an "internal only" resource the
    # scanner can only reach *through* the SSRF sink — never by crawling.
    @app.get("/internal/latest/meta-data/", response_class=PlainTextResponse,
             include_in_schema=False)
    def imds():
        return (
            "ami-id\n"
            "ami-launch-index\n"
            "hostname\n"
            "iam/security-credentials/\n"
            "instance-id\n"
            "instance-type\n"
            "local-ipv4\n"
        )

    # ----- API (this is what oedipus crawls via /openapi.json) -----
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "mode": "safe" if SAFE else "vulnerable"}

    @app.post("/api/register")
    def register(payload: RegisterIn):
        if payload.username in _USERS:
            raise HTTPException(status_code=409, detail="username taken")
        # VULNERABLE: the model bound `admin` straight from the client body.
        # Hardened build ignores it and forces admin=False.
        admin = bool(payload.admin) if not SAFE else False
        user = {
            "username": payload.username,
            "password": payload.password,
            "email": payload.email,
            "tenant": "acme",
            "admin": admin,
            "token": f"tok_{uuid.uuid4().hex[:8]}",
        }
        _USERS[payload.username] = user
        return {"username": user["username"], "email": user["email"], "admin": user["admin"]}

    @app.post("/api/login")
    def login(payload: LoginIn):
        user = _USERS.get(payload.username)
        if not user or user["password"] != payload.password:
            raise HTTPException(status_code=401, detail="bad credentials")
        return {
            "token": _issue_token(user),
            "username": user["username"],
            "tenant": user["tenant"],
            "admin": user["admin"],
        }

    @app.get("/api/me")
    def me(user: dict = Depends(_current_user)):
        # Reachable with an alg=none forgery in the vulnerable build.
        return {"username": user.get("username"), "tenant": user.get("tenant"),
                "admin": user.get("admin", False)}

    @app.get("/api/debug/users")
    def debug_users():
        # VULNERABLE: excessive data exposure — dumps every user's cleartext
        # password and api token. Hardened build removes the endpoint.
        if SAFE:
            raise HTTPException(status_code=404, detail="not found")
        return {"users": list(_USERS.values())}

    @app.post("/api/notes")
    def create_note(payload: NoteIn, user: dict = Depends(_current_user)):
        note = {
            "id": payload.id,
            "title": payload.title,
            "body": payload.body,
            "secret": payload.secret,
            "owner": user["username"],
            "tenant": user.get("tenant"),
        }
        _NOTES[payload.id] = note
        return note

    @app.get("/api/notes/{note_id}")
    def read_note(note_id: str, user: dict = Depends(_current_user)):
        note = _NOTES.get(note_id)
        if note is None:
            raise HTTPException(status_code=404, detail="not found")
        # VULNERABLE: no object-level ownership check — any authenticated user
        # reads any note. Hardened build enforces per-object ownership.
        if SAFE and note.get("owner") != user.get("username"):
            raise HTTPException(status_code=403, detail="forbidden")
        return note

    @app.get("/api/products")
    def list_products():
        return {"products": _list_products()}

    @app.get("/api/products/search")
    def search_products(q: str):
        conn = sqlite3.connect(DB_PATH)
        try:
            if SAFE:
                cur = conn.execute(
                    "SELECT id, name, price FROM products WHERE name LIKE ?",
                    (f"%{q}%",),
                )
            else:
                # VULNERABLE: raw string interpolation -> error-based SQLi.
                cur = conn.execute(
                    "SELECT id, name, price FROM products "
                    f"WHERE name LIKE '%{q}%'"
                )
            rows = [{"id": r[0], "name": r[1], "price": r[2]} for r in cur.fetchall()]
            return {"results": rows}
        except sqlite3.Error as exc:
            # Leak the DB error (the error-based SQLi oracle keys on this).
            return JSONResponse(
                status_code=500,
                content={"error": f"{type(exc).__module__}.{type(exc).__name__}: {exc}"},
            )
        finally:
            conn.close()

    @app.get("/api/products/{product_id}")
    def get_product(product_id: str):
        # Negative lookalike: parameterized query. Injecting quotes here yields
        # no rows and no DB error, so the sqli check must stay silent.
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.execute(
                "SELECT id, name, price FROM products WHERE id = ?", (product_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="not found")
            return {"id": row[0], "name": row[1], "price": row[2]}
        finally:
            conn.close()

    @app.post("/api/url-preview")
    def url_preview(payload: UrlIn = Body(...)):
        # VULNERABLE: fetches an attacker-controlled URL with no egress control
        # and reflects the body. Hardened build enforces the allowlist.
        if SAFE and not _host_allowed(payload.url):
            raise HTTPException(status_code=400, detail="url not allowed")
        return _fetch(payload.url)

    @app.post("/api/url-preview-safe")
    def url_preview_safe(payload: UrlIn = Body(...)):
        # Negative lookalike: always allowlist-enforced. The ssrf check probes
        # this too and must produce nothing.
        if not _host_allowed(payload.url):
            raise HTTPException(status_code=400, detail="url not allowed")
        return _fetch(payload.url)

    return app


# --- helpers --------------------------------------------------------------
def _list_products() -> list[dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute("SELECT id, name, price FROM products ORDER BY id")
        return [{"id": r[0], "name": r[1], "price": r[2]} for r in cur.fetchall()]
    finally:
        conn.close()


def _host_allowed(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in FETCH_ALLOWLIST


def _fetch(url: str) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=3.0, follow_redirects=False) as client:
            resp = client.get(url)
        return {"url": url, "status": resp.status_code, "body": resp.text[:4096]}
    except Exception as exc:  # noqa: BLE001 - preview never crashes the app
        return {"url": url, "status": None, "error": str(exc)}


# Module-level app so `uvicorn vulnapp.app:app` works.
app = create_app()
