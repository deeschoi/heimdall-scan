"""JWT oracles: guessable HMAC secret and ``alg=none`` acceptance.

Weak-secret detection is offline (the wordlist candidate must verify the
target's own signature, RFC 7519), while ``alg=none`` is proven online by an
unsigned forgery being accepted on a protected route (WSTG-SESS-10).
"""

import base64
import json

import httpx
import jwt as pyjwt
import pytest
import respx

from heimdall.auth import Identity
from heimdall.checks.jwt import JwtCheck
from heimdall.models import Severity

from .conftest import BASE

# Short lab secrets are the point of these tests; PyJWT's length advice is noise
# here (the check installs the same filter at import time, but pytest resets it).
pytestmark = pytest.mark.filterwarnings("ignore:The HMAC key")

STRONG_SECRET = "Ok7kq5Xz-heimdall-not-in-any-wordlist-2f91b0"
PROTECTED = {"path": "/me", "method": "GET"}


def _token(secret: str, payload: dict | None = None, alg: str = "HS256") -> str:
    return pyjwt.encode(payload or {"sub": "user_a", "role": "user"}, secret, algorithm=alg)


def _ctx(make_ctx, token, cfg=None, **kwargs):
    return make_ctx(
        identities={
            "anon": Identity(name="anon"),
            "user_a": Identity(
                name="user_a", headers={"Authorization": f"Bearer {token}"}, token=token
            ),
        },
        extras={"jwt": cfg if cfg is not None else {"identity": "user_a"}},
        **kwargs,
    )


def _decode_header(token: str) -> dict:
    seg = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def test_guessable_secret_is_reported(make_ctx):
    findings = JwtCheck().run(_ctx(make_ctx, _token("secret")))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "jwt"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-347"
    assert f.owasp_api == "API2:2023"
    assert "weak" in f.title.lower()
    assert "'secret'" in f.evidence[0].matcher
    # Verified offline: no request should have been needed.
    assert f.evidence[0].request_method == "-"


def test_strong_secret_is_silent(make_ctx):
    assert JwtCheck().run(_ctx(make_ctx, _token(STRONG_SECRET))) == []


def test_secret_wordlist_from_payloads_dir_is_used(make_ctx, payloads_dir):
    lab_secret = "heimdall-lab-key"
    directory = payloads_dir("jwt-secrets.txt", ["# curated list", "", lab_secret, "hunter2"])

    findings = JwtCheck().run(
        _ctx(make_ctx, _token(lab_secret), payloads_dir=directory)
    )

    assert len(findings) == 1
    assert repr(lab_secret) in findings[0].evidence[0].matcher


def test_wordlist_replaces_the_builtin_defaults(make_ctx, payloads_dir):
    """With a payload file present the built-in defaults must not be tried."""
    directory = payloads_dir("jwt-secrets.txt", ["hunter2", "letmein"])

    assert JwtCheck().run(_ctx(make_ctx, _token("secret"), payloads_dir=directory)) == []


def test_expired_token_still_reveals_a_weak_secret(make_ctx):
    """Signature verification, not claim validity, is the oracle here."""
    token = _token("changeme", {"sub": "user_a", "exp": 1_000_000_000})

    findings = JwtCheck().run(_ctx(make_ctx, token))

    assert len(findings) == 1
    assert "'changeme'" in findings[0].evidence[0].matcher


def test_asymmetric_algorithm_is_not_brute_forced(make_ctx):
    """HMAC guessing only applies to HS*; an RS256 header must be skipped."""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(b'{"sub":"user_a"}').rstrip(b"=").decode()
    token = f"{header}.{body}.c2ln"

    ctx = _ctx(make_ctx, token)
    assert JwtCheck()._weak_secret(ctx, token) is None
    assert JwtCheck().run(ctx) == []


def test_identity_without_a_token_is_silent(make_ctx):
    ctx = make_ctx(identities={"anon": Identity(name="anon")}, extras={"jwt": {}})
    assert JwtCheck().run(ctx) == []


def test_falls_back_to_any_token_bearing_identity(make_ctx):
    """No ``identity`` configured: pick whichever identity carries a token."""
    token = _token("admin")
    ctx = make_ctx(
        identities={
            "anon": Identity(name="anon"),
            "user_b": Identity(name="user_b", token=token),
        },
        extras={"jwt": {}},
    )

    findings = JwtCheck().run(ctx)
    assert len(findings) == 1
    assert "'admin'" in findings[0].evidence[0].matcher


@respx.mock
def test_alg_none_accepted_is_critical(make_ctx):
    route = respx.get(f"{BASE}/me").mock(
        return_value=httpx.Response(200, json={"username": "user_a", "admin": False})
    )

    findings = JwtCheck().run(
        _ctx(
            make_ctx,
            _token(STRONG_SECRET),
            {"identity": "user_a", "protected": PROTECTED},
        )
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert "alg=none" in f.title
    assert f.path_template == "/me"
    assert f.method == "GET"
    assert "alg=none token accepted (HTTP 200)" in f.evidence[0].matcher

    # The forged credential must genuinely be unsigned, and carry the real claims.
    sent = route.calls.last.request.headers["authorization"].removeprefix("Bearer ")
    assert _decode_header(sent)["alg"] == "none"
    assert sent.endswith(".")
    claims = pyjwt.decode(sent, options={"verify_signature": False})
    assert claims["sub"] == "user_a"


@respx.mock
def test_alg_none_rejected_is_silent(make_ctx):
    respx.get(f"{BASE}/me").mock(
        return_value=httpx.Response(401, json={"detail": "invalid algorithm"})
    )

    findings = JwtCheck().run(
        _ctx(
            make_ctx,
            _token(STRONG_SECRET),
            {"identity": "user_a", "protected": PROTECTED},
        )
    )

    assert findings == []


@respx.mock
def test_both_weaknesses_reported_together(make_ctx):
    respx.get(f"{BASE}/me").mock(return_value=httpx.Response(200, json={"ok": True}))

    findings = JwtCheck().run(
        _ctx(make_ctx, _token("secret"), {"identity": "user_a", "protected": PROTECTED})
    )

    assert [f.severity for f in findings] == [Severity.HIGH, Severity.CRITICAL]


@respx.mock
def test_no_protected_route_configured_skips_the_forgery_probe(make_ctx):
    route = respx.get(f"{BASE}/me").mock(return_value=httpx.Response(200))

    JwtCheck().run(_ctx(make_ctx, _token(STRONG_SECRET), {"identity": "user_a"}))

    assert not route.called
