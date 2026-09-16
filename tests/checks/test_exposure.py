"""Excessive data exposure: which endpoints get probed, and what counts as a leak.

``test_checks_oracles.py`` covers ``_leaked_keys``; these tests cover the crawl
policy around it (WSTG-ATHZ-04 / API3:2023) — collection endpoints are read,
object-id endpoints are left to BOLA, and denied responses are not "leaks".
"""

import httpx
import respx

from heimdall.checks.exposure import ExposureCheck
from heimdall.crawler import parse_endpoints
from heimdall.models import Severity

from .conftest import BASE

LEAKY_BODY = {
    "users": [
        {"username": "alice", "password": "pass1", "email": "a@b.com"},
        {"username": "bob", "password": "pass2", "email": "b@b.com"},
    ]
}

SPEC = {
    "paths": {
        "/users/v1/_debug": {"get": {}},
        "/books/v1": {"get": {}},
        "/users/v1/{username}": {
            "get": {
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ]
            }
        },
    }
}


def _ctx(make_ctx, spec=SPEC):
    return make_ctx(endpoints=parse_endpoints(spec))


@respx.mock
def test_debug_dump_of_credentials_is_reported(make_ctx):
    respx.get(f"{BASE}/users/v1/_debug").mock(return_value=httpx.Response(200, json=LEAKY_BODY))
    respx.get(f"{BASE}/books/v1").mock(
        return_value=httpx.Response(200, json={"books": [{"title": "t"}]})
    )
    keyed = respx.get(url__startswith=f"{BASE}/users/v1/1").mock(
        return_value=httpx.Response(200, json={"password": "leak"})
    )

    findings = ExposureCheck().run(_ctx(make_ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "exposure"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-200"
    assert f.owasp_api == "API3:2023"
    assert f.path_template == "/users/v1/_debug"
    assert "['password']" in f.evidence[0].matcher
    # Object-keyed endpoints belong to BOLA, so this check never touches them.
    assert not keyed.called


@respx.mock
def test_endpoint_returning_only_public_fields_is_silent(make_ctx):
    respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"username": "alice"}]})
    )
    respx.get(f"{BASE}/books/v1").mock(return_value=httpx.Response(200, json={"books": []}))

    assert ExposureCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_denied_debug_endpoint_is_not_a_leak(make_ctx):
    """A 403 body that mentions a secret field is not exposed data."""
    respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(403, json={"detail": "admin only", "token": "nope"})
    )
    respx.get(f"{BASE}/books/v1").mock(return_value=httpx.Response(200, json={"books": []}))

    assert ExposureCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_every_leaking_collection_is_reported(make_ctx):
    spec = {"paths": {"/a": {"get": {}}, "/b": {"get": {}}}}
    respx.get(f"{BASE}/a").mock(return_value=httpx.Response(200, json={"secret": "s"}))
    respx.get(f"{BASE}/b").mock(return_value=httpx.Response(200, json={"cvv": "123"}))

    findings = ExposureCheck().run(_ctx(make_ctx, spec))

    assert {f.path_template for f in findings} == {"/a", "/b"}


@respx.mock
def test_unreachable_endpoint_does_not_abort_the_sweep(make_ctx):
    spec = {"paths": {"/a": {"get": {}}, "/b": {"get": {}}}}
    respx.get(f"{BASE}/a").mock(side_effect=httpx.ConnectError("down"))
    respx.get(f"{BASE}/b").mock(return_value=httpx.Response(200, json={"ssn": "1"}))

    findings = ExposureCheck().run(_ctx(make_ctx, spec))

    assert [f.path_template for f in findings] == ["/b"]


def test_leaked_keys_falls_back_to_regex_on_non_json():
    c = ExposureCheck()
    html = '<pre>{"username": "alice", "Password": "hunter2"}</pre>'
    assert c._leaked_keys(html) == {"password"}


def test_leaked_keys_reports_every_distinct_field():
    c = ExposureCheck()
    body = '{"a": {"token": "t"}, "b": [{"credit_card": "4111", "cvv": "123"}]}'
    assert c._leaked_keys(body) == {"token", "credit_card", "cvv"}


def test_leaked_keys_ignores_similarly_named_fields():
    c = ExposureCheck()
    assert c._leaked_keys('{"password_hint": "x", "reset_token_sent": true}') == set()
