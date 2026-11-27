"""Evidence capture: what HttpClient records, and what it must never record.

Findings are serialized verbatim into JSON/SARIF/Markdown reports, so any
credential captured here leaks into every artifact a scan produces.
"""

import httpx
import respx

from heimdall.http_client import HttpClient
from heimdall.scope import Scope

BASE = "http://127.0.0.1:8000"


@respx.mock
def test_authorization_header_is_not_captured_in_evidence():
    respx.get(f"{BASE}/me").mock(return_value=httpx.Response(200, text="ok"))
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        response = client.request(
            "GET",
            f"{BASE}/me",
            headers={"Authorization": "Bearer SUPERSECRET", "X-Trace-Id": "abc123"},
        )
        evidence = client.evidence_from(response)
    finally:
        client.close()

    names = {k.lower() for k in evidence.request_headers}
    assert "authorization" not in names
    assert "SUPERSECRET" not in str(evidence.request_headers)
    assert evidence.request_headers["x-trace-id"] == "abc123"


@respx.mock
def test_credential_headers_are_redacted_in_evidence():
    respx.get(f"{BASE}/me").mock(
        return_value=httpx.Response(
            200,
            text="ok",
            headers={"Set-Cookie": "session=SECRET", "X-Trace-Id": "abc"},
        )
    )
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        response = client.request(
            "GET",
            f"{BASE}/me",
            headers={
                "Cookie": "sid=SECRET",
                "X-Api-Key": "KEY",
                "X-Trace-Id": "abc123",
            },
        )
        evidence = client.evidence_from(response)
    finally:
        client.close()

    names = {k.lower() for k in evidence.request_headers}
    assert "cookie" not in names
    assert "x-api-key" not in names
    assert "SECRET" not in str(evidence.request_headers)
    assert "KEY" not in str(evidence.request_headers)
    assert evidence.request_headers["x-trace-id"] == "abc123"

    response_headers = {k.lower(): v for k, v in evidence.response_headers.items()}
    assert response_headers["set-cookie"] == "[REDACTED]"
    assert "SECRET" not in response_headers["set-cookie"]
    assert response_headers["x-trace-id"] == "abc"


# --- identity credentials under any header name (F8) -----------------------

from heimdall.auth import build_identities  # noqa: E402


@respx.mock
def test_identity_token_in_custom_header_is_kept_out_of_evidence():
    respx.get(f"{BASE}/notes/1").mock(
        return_value=httpx.Response(200, text='{"echo": "tok-ABCDEF123456"}')
    )
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        idents = build_identities(
            BASE,
            {"user_b": {"type": "bearer", "token": "tok-ABCDEF123456",
                        "header": "X-Access-Token", "prefix": ""}},
            client,
        )
        resp = client.request("GET", f"{BASE}/notes/1", headers=idents["user_b"].apply())
        evidence = client.evidence_from(resp)
    finally:
        client.close()

    dumped = str(evidence)
    assert "tok-ABCDEF123456" not in dumped
    assert "x-access-token" not in {k.lower() for k in evidence.request_headers}
    assert "[REDACTED]" in evidence.response_body_excerpt


@respx.mock
def test_credential_looking_header_names_are_dropped():
    respx.get(f"{BASE}/me").mock(return_value=httpx.Response(200, text="ok"))
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        resp = client.request(
            "GET", f"{BASE}/me",
            headers={"X-Session-Token": "s1", "Api-Key": "k1", "X-Trace-Id": "t1"},
        )
        evidence = client.evidence_from(resp)
    finally:
        client.close()
    names = {k.lower() for k in evidence.request_headers}
    assert "x-session-token" not in names
    assert "api-key" not in names
    assert evidence.request_headers["x-trace-id"] == "t1"


# --- user:pass@ in a URL (F13) ---------------------------------------------

@respx.mock
def test_url_userinfo_becomes_basic_auth_and_never_reaches_evidence():
    route = respx.get(f"{BASE}/x").mock(
        return_value=httpx.Response(200, text="hello hunter2-pass")
    )
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        resp = client.request("GET", "http://svc:hunter2-pass@127.0.0.1:8000/x")
        evidence = client.evidence_from(resp)
    finally:
        client.close()
    sent = route.calls.last.request
    assert sent.headers["authorization"].startswith("Basic ")
    assert evidence.request_url == f"{BASE}/x"
    assert "hunter2-pass" not in str(evidence)


def test_split_userinfo():
    from heimdall.http_client import split_userinfo

    assert split_userinfo("http://u:p@h:1/a?b") == ("http://h:1/a?b", ("u", "p"))
    assert split_userinfo("http://h/a") == ("http://h/a", None)


# --- methods (F12) ---------------------------------------------------------

import pytest  # noqa: E402


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "MOVE", "PURGE", "TRACE"])
def test_state_changing_and_unknown_methods_need_unsafe(method):
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
    try:
        with pytest.raises(PermissionError):
            client.request(method, f"{BASE}/x")
    finally:
        client.close()


# --- pinned connections and redirects (F17) --------------------------------

@respx.mock
def test_pinned_host_connects_to_the_vetted_address(monkeypatch):
    scope = Scope.from_targets(["http://lab.example:8000"])
    scope.pinned["lab.example"] = ["10.0.0.7"]
    route = respx.get("http://10.0.0.7:8000/x").mock(return_value=httpx.Response(200))
    client = HttpClient(scope, rate_limit_per_sec=0)
    try:
        resp = client.request("GET", "http://lab.example:8000/x")
    finally:
        client.close()
    assert route.called
    assert route.calls.last.request.headers["host"] == "lab.example:8000"
    # Evidence still names the host the operator asked for.
    assert str(resp.request.url) == "http://lab.example:8000/x"


@respx.mock
def test_redirect_out_of_scope_is_refused():
    from heimdall.scope import ScopeError

    respx.get(f"{BASE}/go").mock(
        return_value=httpx.Response(302, headers={"Location": "http://10.9.9.9/admin"})
    )
    client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0, follow_redirects=True)
    try:
        with pytest.raises(ScopeError):
            client.request("GET", f"{BASE}/go")
    finally:
        client.close()
