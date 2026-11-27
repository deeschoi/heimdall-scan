from heimdall.crawler import parse_endpoints, fill_path

SPEC = {
    "paths": {
        "/users/v1/{username}": {
            "get": {
                "summary": "get user",
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ],
            }
        },
        "/books/v1": {
            "get": {"summary": "list"},
            "post": {
                "summary": "add",
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
            },
        },
    }
}


def test_parse_endpoints_counts_operations():
    eps = parse_endpoints(SPEC)
    keys = {(e.method, e.path_template) for e in eps}
    assert ("GET", "/users/v1/{username}") in keys
    assert ("GET", "/books/v1") in keys
    assert ("POST", "/books/v1") in keys


def test_path_params_detected():
    eps = parse_endpoints(SPEC)
    user_get = next(e for e in eps if e.path_template == "/users/v1/{username}")
    assert [p.name for p in user_get.path_params] == ["username"]


def test_request_body_schema_captured():
    eps = parse_endpoints(SPEC)
    post = next(e for e in eps if e.method == "POST")
    assert post.request_body_schema == {"type": "object"}


def test_fill_path():
    assert fill_path("/users/v1/{username}", {"username": "admin'"}) == "/users/v1/admin'"


# --- hostile spec paths (F18) ----------------------------------------------

import httpx  # noqa: E402
import pytest  # noqa: E402
import respx  # noqa: E402

from heimdall.checks import ScanContext  # noqa: E402
from heimdall.crawler import load_spec  # noqa: E402
from heimdall.http_client import HttpClient  # noqa: E402
from heimdall.scope import Scope, ScopeError  # noqa: E402


@pytest.mark.parametrize(
    "path",
    ["@127.0.0.1:2375/containers/json", "users", "\\\\evil/x", "/ok\x1b[2K", "/a\x9b1A"],
)
def test_unrooted_or_control_char_paths_are_skipped(path):
    eps = parse_endpoints({"paths": {path: {"get": {}}, "/fine": {"get": {}}}})
    assert [e.path_template for e in eps] == ["/fine"]


def test_rooted_path_with_at_sign_is_kept():
    eps = parse_endpoints({"paths": {"/users/@me": {"get": {}}}})
    assert [e.path_template for e in eps] == ["/users/@me"]


def test_context_url_refuses_paths_that_leave_the_base_authority():
    client = HttpClient(Scope.from_targets(["http://127.0.0.1:8000"]), rate_limit_per_sec=0)
    try:
        ctx = ScanContext(base_url="http://127.0.0.1:8000", client=client)
        assert ctx.url("/x?y=1") == "http://127.0.0.1:8000/x?y=1"
        with pytest.raises(ScopeError):
            ctx.url("@127.0.0.1:2375/containers/json")
        with pytest.raises(ScopeError):
            ctx.url(":2375/x")
    finally:
        client.close()


# --- spec fetch goes through the scan's client (F7) ------------------------

def test_spec_url_without_client_is_refused():
    with pytest.raises(ValueError):
        load_spec("https://127.0.0.1:8443/openapi.json")


@respx.mock
def test_spec_fetch_is_scope_checked():
    client = HttpClient(Scope.from_targets(["http://127.0.0.1:8000"]), rate_limit_per_sec=0)
    try:
        with pytest.raises(ScopeError):
            load_spec("http://10.1.2.3/openapi.json", client)
    finally:
        client.close()


def test_engine_fetches_spec_with_the_scans_tls_policy(monkeypatch):
    import heimdall.engine as engine

    seen = {}

    def fake_load_spec(source, client=None):
        seen["client"] = client
        return {"paths": {}}

    monkeypatch.setattr(engine, "load_spec", fake_load_spec)
    engine.scan("https://127.0.0.1:8443", ["exposure"],
                openapi="https://127.0.0.1:8443/openapi.json", rate_limit=0)
    assert isinstance(seen["client"], HttpClient)
    assert seen["client"].verify_tls is True
