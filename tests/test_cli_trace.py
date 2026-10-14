"""`heimdall scan` streams a transcript on stderr and keeps machine stdout clean."""

import json

import httpx
import respx
from click.testing import CliRunner

from heimdall.cli import main

BASE = "http://127.0.0.1:8000"
SPEC_URL = f"{BASE}/openapi.json"
SQL_ERROR = "sqlite3.OperationalError: unrecognized token"

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/search": {
            "get": {
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}}
                ]
            }
        },
        "/users/v1/{username}": {
            "get": {
                "parameters": [
                    {
                        "name": "username",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ]
            }
        },
    },
}


def _mock() -> None:
    respx.get(SPEC_URL).mock(return_value=httpx.Response(200, json=SPEC))
    respx.get(f"{BASE}/search").mock(return_value=httpx.Response(200, json={"ok": True}))
    respx.get(url__startswith=f"{BASE}/users/v1/").mock(
        return_value=httpx.Response(500, text=SQL_ERROR)
    )


def _out(result) -> str:
    return result.stdout or result.output or ""


def _err(result) -> str:
    return result.stderr or ""


@respx.mock
def test_default_scan_prints_the_check_and_a_hit():
    _mock()
    result = CliRunner().invoke(
        main,
        ["scan", "--target", BASE, "--check", "sqli", "--format", "json", "--rate-limit", "0"],
    )
    assert result.exit_code == 0, result.output
    stdout = _out(result)
    doc = json.loads(stdout)
    assert "How the scan went" not in stdout
    assert "trace" not in doc
    err = _err(result)
    assert "sqli" in err
    assert "[HIGH]" in err
    assert "sending" not in err


@respx.mock
def test_quiet_scan_has_no_transcript():
    _mock()
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--target",
            BASE,
            "--check",
            "sqli",
            "--format",
            "md",
            "--rate-limit",
            "0",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    text = _out(result)
    assert "## How the scan went" not in text
    assert "Trying a quote" not in text
    assert "Trying a quote" not in _err(result)
    assert "# Heimdall scan report" in text


@respx.mock
def test_markdown_report_leads_with_the_transcript():
    _mock()
    result = CliRunner().invoke(
        main,
        ["scan", "--target", BASE, "--check", "sqli", "--format", "md", "--rate-limit", "0"],
    )
    assert result.exit_code == 0, result.output
    text = _out(result)
    assert "## How the scan went" in text
    assert "sqli" in text
    assert "[HIGH]" in text
    assert "sending" not in text
    assert "sqli" in _err(result)


@respx.mock
def test_verbose_lists_payloads_on_stderr_only():
    _mock()
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--target",
            BASE,
            "--check",
            "sqli",
            "--format",
            "md",
            "--rate-limit",
            "0",
            "--verbose",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "sending" in _err(result)
    assert "sending" not in _out(result)
