"""Error-based SQLi: crawl-driven injection plus the engine-error oracle.

``test_checks_oracles.py`` covers the signature oracle in isolation; these tests
cover the surrounding technique (WSTG-INPV-05): which endpoints/parameters get a
payload, that the wordlist is honored, and that one endpoint yields one finding.
"""

from urllib.parse import unquote

import httpx
import respx

from oedipus.checks.sqli import SqliCheck
from oedipus.crawler import parse_endpoints
from oedipus.models import Severity

from .conftest import BASE

SQL_ERROR = (
    "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) "
    'unrecognized token: "\'" [SQL: SELECT * FROM users WHERE name = \'admin\'\']'
)

SPEC = {
    "paths": {
        "/users/v1/{username}": {
            "get": {
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ]
            }
        },
        "/books/v1": {"get": {}},
    }
}


def _ctx(make_ctx, spec=SPEC, **kwargs):
    return make_ctx(endpoints=parse_endpoints(spec), **kwargs)


@respx.mock
def test_database_error_on_injected_path_param_is_reported(make_ctx):
    vuln = respx.get(url__startswith=f"{BASE}/users/v1/").mock(
        return_value=httpx.Response(500, text=SQL_ERROR)
    )
    safe = respx.get(f"{BASE}/books/v1").mock(
        return_value=httpx.Response(200, json={"books": []})
    )

    findings = SqliCheck().run(_ctx(make_ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "sqli"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-89"
    assert f.owasp_api == "API8:2023"
    assert f.method == "GET"
    assert f.path_template == "/users/v1/{username}"
    assert "sqlalchemy.exc.OperationalError" in f.evidence[0].matcher
    assert "payload=" in f.evidence[0].matcher
    # One confirmed injection per endpoint: it stops at the first firing payload.
    assert vuln.call_count == 1
    # An endpoint with no injectable parameter is never probed.
    assert not safe.called


@respx.mock
def test_parameterized_query_is_silent(make_ctx):
    """The hardened lookalike route: 404/200 with no engine error, several payloads."""
    route = respx.get(url__startswith=f"{BASE}/users/v1/").mock(
        return_value=httpx.Response(404, json={"detail": "user not found"})
    )

    assert SqliCheck().run(_ctx(make_ctx)) == []
    assert route.call_count == 4  # every default payload tried, none fired


@respx.mock
def test_query_parameters_are_injected(make_ctx):
    spec = {
        "paths": {
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                    ]
                }
            }
        }
    }
    route = respx.get(f"{BASE}/search").mock(return_value=httpx.Response(500, text=SQL_ERROR))

    findings = SqliCheck().run(_ctx(make_ctx, spec))

    assert len(findings) == 1
    assert findings[0].path_template == "/search"
    assert route.calls.last.request.url.params["q"] == "'"


@respx.mock
def test_payload_file_overrides_the_defaults(make_ctx, payloads_dir):
    directory = payloads_dir("sqli.txt", ["# curated", "OEDIPUS_SQLI_MARK'"])
    route = respx.get(url__startswith=f"{BASE}/users/v1/").mock(
        return_value=httpx.Response(500, text=SQL_ERROR)
    )

    findings = SqliCheck().run(_ctx(make_ctx, payloads_dir=directory))

    assert len(findings) == 1
    assert "OEDIPUS_SQLI_MARK'" in unquote(str(route.calls.last.request.url))


@respx.mock
def test_non_get_operations_are_not_probed(make_ctx):
    """Injection into write methods would mutate the target; it must be skipped."""
    spec = {
        "paths": {
            "/books/v1": {
                "post": {
                    "parameters": [
                        {"name": "title", "in": "query", "schema": {"type": "string"}}
                    ]
                }
            }
        }
    }
    route = respx.route(host="127.0.0.1").mock(return_value=httpx.Response(500, text=SQL_ERROR))

    assert SqliCheck().run(_ctx(make_ctx, spec)) == []
    assert not route.called


@respx.mock
def test_error_page_without_a_sql_signature_is_silent(make_ctx):
    """A generic 500 is not evidence of injection."""
    respx.get(url__startswith=f"{BASE}/users/v1/").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    assert SqliCheck().run(_ctx(make_ctx)) == []


def test_oracle_covers_more_engine_signatures():
    c = SqliCheck()
    assert c.oracle(500, "ORA-00933: SQL command not properly ended")
    assert c.oracle(500, "SQLSTATE[42000]: Syntax error")
    assert c.oracle(500, "Unclosed quotation mark after the character string")
    assert c.oracle(200, "sqlite3.OperationalError: unrecognized token")  # status-agnostic
    assert not c.oracle(500, "Internal Server Error")
