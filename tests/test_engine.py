"""Suite loading and scan wiring, against a mocked target (no live server).

These tests pin the engine's contract: crawl the OpenAPI document, build the
declared identities, hand hints to the right checks, honor the exclude list,
de-duplicate on fingerprint, and never let one broken check abort a scan.
"""

import json

import httpx
import jwt as pyjwt
import pytest
import respx
import yaml

from heimdall.checks import Check, ScanContext
from heimdall.engine import Suite, scan, scan_suite

BASE = "http://127.0.0.1:8000"
SPEC_URL = f"{BASE}/openapi.json"

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/users/v1/_debug": {"get": {"summary": "debug dump"}},
        "/createdb": {"get": {"summary": "reset the database"}},
        "/users/v1/{username}": {
            "get": {
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ]
            }
        },
    },
}

SQL_ERROR = "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token"
CANARY = "HEIMDALL_CANARY_7f3a"

BOLA_HINT = {
    "create": {"path": "/invoices", "method": "POST", "as": "user_a",
               "json": {"secret": CANARY}},
    "read": {"path": "/invoices/1", "method": "GET", "as": "user_b"},
    "canary": CANARY,
}


def _mock_spec():
    return respx.get(SPEC_URL).mock(return_value=httpx.Response(200, json=SPEC))


def _write_suite(tmp_path, **overrides) -> str:
    data = {
        "name": "mocktarget",
        "target": BASE,
        "openapi": SPEC_URL,
        "checks": ["exposure"],
        "safe_target": "http://127.0.0.1:8001",
        "expected": "mocktarget.expected.json",
        "auth": {"user_a": {"type": "bearer", "token": "TOK-A"}},
        "hints": {"bola": [BOLA_HINT]},
        "exclude": ["/createdb"],
        "payloads_dir": "../payloads",
    }
    data.update(overrides)
    p = tmp_path / "mocktarget.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


# --- Suite loading ----------------------------------------------------


def test_suite_load_parses_every_field(tmp_path):
    suite = Suite.load(_write_suite(tmp_path))

    assert suite.name == "mocktarget"
    assert suite.target == BASE
    assert suite.openapi == SPEC_URL
    assert suite.checks == ["exposure"]
    assert suite.safe_target == "http://127.0.0.1:8001"
    assert suite.expected == "mocktarget.expected.json"
    assert suite.exclude == ["/createdb"]
    assert suite.auth["user_a"]["token"] == "TOK-A"
    assert suite.hints["bola"][0]["canary"] == CANARY


def test_suite_name_defaults_to_filename(tmp_path):
    path = tmp_path / "vampi.yaml"
    path.write_text(yaml.safe_dump({"target": BASE, "checks": []}), encoding="utf-8")
    assert Suite.load(str(path)).name == "vampi"


def test_suite_requires_a_target(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text(yaml.safe_dump({"checks": ["sqli"]}), encoding="utf-8")
    with pytest.raises(KeyError):
        Suite.load(str(path))


def test_suite_resolve_is_relative_to_the_yaml(tmp_path):
    suite = Suite.load(_write_suite(tmp_path))
    resolved = suite.resolve(suite.payloads_dir)

    assert resolved == (tmp_path / ".." / "payloads").resolve()
    assert resolved.is_absolute()
    assert suite.resolve(None) is None
    assert suite.resolve("/abs/payloads").as_posix() == "/abs/payloads"


# --- scan() wiring ----------------------------------------------------


@respx.mock
def test_scan_crawls_the_spec_and_runs_each_check():
    spec = _mock_spec()
    debug = respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"username": "a", "password": "p"}]})
    )
    respx.get(url__startswith=f"{BASE}/users/v1/1").mock(
        return_value=httpx.Response(500, text=SQL_ERROR)
    )

    findings = scan(BASE, ["exposure", "sqli"], openapi=SPEC_URL, rate_limit=0)

    assert spec.called
    assert debug.called
    assert {f.check_id for f in findings} == {"exposure", "sqli"}
    assert {f.path_template for f in findings} == {
        "/users/v1/_debug",
        "/users/v1/{username}",
    }


@respx.mock
def test_scan_never_requests_excluded_endpoints():
    _mock_spec()
    createdb = respx.get(f"{BASE}/createdb").mock(
        return_value=httpx.Response(200, json={"secret": "leaked"})
    )
    respx.get(f"{BASE}/users/v1/_debug").mock(return_value=httpx.Response(200, json={}))

    findings = scan(
        BASE, ["exposure"], openapi=SPEC_URL, exclude=["/createdb"], rate_limit=0
    )

    assert not createdb.called
    assert findings == []


@respx.mock
def test_scan_survives_an_unreachable_openapi_document():
    respx.get(SPEC_URL).mock(return_value=httpx.Response(404, text="not found"))
    probe = respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200))

    assert scan(BASE, ["exposure", "sqli"], openapi=SPEC_URL, rate_limit=0) == []
    assert not probe.called


@respx.mock
def test_scan_passes_bearer_identities_to_checks():
    read = respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, json={"secret": CANARY})
    )
    respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201))

    findings = scan(
        BASE,
        ["bola"],
        auth={
            "user_a": {"type": "bearer", "token": "TOK-A"},
            "user_b": {"type": "bearer", "token": "TOK-B"},
        },
        hints={"bola": [BOLA_HINT]},
        rate_limit=0,
    )

    assert len(findings) == 1
    assert read.calls.last.request.headers["authorization"] == "Bearer TOK-B"


@respx.mock
@pytest.mark.filterwarnings("ignore:The HMAC key")
def test_scan_logs_in_and_feeds_the_token_to_the_jwt_check():
    """The login adapter's extracted token is what the JWT check attacks."""
    token = pyjwt.encode({"sub": "user_a"}, "secret", algorithm="HS256")
    login = respx.post(f"{BASE}/users/v1/login").mock(
        return_value=httpx.Response(200, json={"auth_token": token})
    )

    findings = scan(
        BASE,
        ["jwt"],
        auth={
            "user_a": {
                "type": "login",
                "login": {"path": "/users/v1/login",
                          "json": {"username": "a", "password": "b"},
                          "token_field": "auth_token"},
            }
        },
        hints={"jwt": {"identity": "user_a"}},
        rate_limit=0,
    )

    assert login.called
    assert len(findings) == 1
    assert "'secret'" in findings[0].evidence[0].matcher


@respx.mock
def test_scan_deduplicates_on_fingerprint():
    respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201))
    respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, json={"secret": CANARY})
    )

    findings = scan(
        BASE,
        ["bola"],
        auth={"user_b": {"type": "bearer", "token": "TOK-B"}},
        hints={"bola": [BOLA_HINT, dict(BOLA_HINT)]},
        rate_limit=0,
    )

    assert len(findings) == 1


@respx.mock
def test_a_broken_check_does_not_abort_the_scan(monkeypatch, capsys):
    from heimdall import engine
    from heimdall.checks import get_check as real_get_check

    class Boom(Check):
        id = "boom"

        def run(self, ctx: ScanContext):
            raise RuntimeError("check exploded")

    monkeypatch.setattr(
        engine, "get_check", lambda cid: Boom() if cid == "boom" else real_get_check(cid)
    )
    _mock_spec()
    respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"token": "leaked"})
    )

    findings = scan(BASE, ["boom", "exposure"], openapi=SPEC_URL, rate_limit=0)

    assert [f.check_id for f in findings] == ["exposure"]
    assert "check boom errored: check exploded" in capsys.readouterr().err


def test_scan_rejects_an_unknown_check():
    with pytest.raises(KeyError):
        scan(BASE, ["not-a-check"], rate_limit=0)


@respx.mock
def test_scan_blocks_destructive_methods_unless_unsafe():
    """A hint asking for a PATCH is refused by the client, not silently sent."""
    patch = respx.patch(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, json={"secret": CANARY})
    )
    hint = {"read": {"path": "/invoices/1", "method": "PATCH", "as": "anon"},
            "canary": CANARY}

    assert scan(BASE, ["bola"], hints={"bola": [hint]}, rate_limit=0) == []
    assert not patch.called

    assert len(scan(BASE, ["bola"], hints={"bola": [hint]}, unsafe=True, rate_limit=0)) == 1
    assert patch.called


# --- scan_suite() -----------------------------------------------------


@respx.mock
def test_scan_suite_forwards_spec_hints_and_payloads(tmp_path):
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    (payloads / "sqli.txt").write_text("# curated\nHEIMDALL_SQLI_MARK'\n", encoding="utf-8")

    suite_path = _write_suite(
        tmp_path,
        checks=["sqli", "exposure"],
        payloads_dir="payloads",
        hints={},
        auth={},
    )

    _mock_spec()
    respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"password": "p"}]})
    )
    injected = respx.get(url__startswith=f"{BASE}/users/v1/HEIMDALL_SQLI_MARK").mock(
        return_value=httpx.Response(500, text=SQL_ERROR)
    )

    findings = scan_suite(Suite.load(suite_path), rate_limit=0)

    assert injected.called, "suite payloads_dir was not passed through to the check"
    assert {f.check_id for f in findings} == {"sqli", "exposure"}


@respx.mock
def test_scan_suite_findings_serialize_for_reporters(tmp_path):
    _mock_spec()
    respx.get(f"{BASE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"password": "p"}]})
    )
    respx.get(url__startswith=f"{BASE}/users/v1/1").mock(return_value=httpx.Response(404))

    findings = scan_suite(Suite.load(_write_suite(tmp_path, hints={}, auth={})), rate_limit=0)

    assert len(findings) == 1
    doc = json.loads(json.dumps(findings[0].to_dict()))
    assert doc["check_id"] == "exposure"
    assert doc["severity"] == "high"
    assert len(doc["fingerprint"]) == 12
    assert doc["evidence"][0]["response_status"] == 200
