"""Scan transcript: plain lines, the Markdown lead-in, and a quiet JSON report."""

import json

from heimdall.checks import TraceEvent
from heimdall.models import Evidence, Finding, Severity
from heimdall.report import render
from heimdall.report.trace import format_plain, markdown_section


def _finding() -> Finding:
    return Finding(
        check_id="sqli",
        title="Error-based SQL injection",
        severity=Severity.HIGH,
        cwe="CWE-89",
        owasp_api="API8:2023",
        wstg="WSTG-INPV-05",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        method="GET",
        path_template="/api/products/search",
        url="http://127.0.0.1:8000/api/products/search?q=%27",
        evidence=[Evidence(request_method="GET", request_url="http://x", matcher="err")],
    )


def _events() -> list[TraceEvent]:
    finding = _finding()
    return [
        TraceEvent(check_id="sqli", kind="check", text="sqli"),
        TraceEvent(
            check_id="sqli",
            kind="step",
            text="GET /api/products/search has a string query `q`. Trying a quote.",
        ),
        TraceEvent(check_id="sqli", kind="step", text="sending \"'\"", verbose=True),
        TraceEvent(check_id="sqli", kind="miss", text="HTTP 200, no SQL error."),
        TraceEvent(
            check_id="sqli",
            kind="hit",
            text="sqlite3.OperationalError in the body.",
            finding=finding,
        ),
    ]


def test_plain_transcript_hides_verbose_payloads():
    text = format_plain(_events())
    assert text.splitlines() == [
        "sqli",
        "  GET /api/products/search has a string query `q`. Trying a quote.",
        "  HTTP 200, no SQL error.",
        "  [HIGH] sqli  GET /api/products/search  CWE-89",
        "        sqlite3.OperationalError in the body.",
    ]
    assert 'sending' in format_plain(_events(), verbose=True)


def test_markdown_section_uses_the_default_lines():
    section = markdown_section(_events())
    assert section.startswith("## How the scan went\n")
    assert "Trying a quote." in section
    assert "[HIGH] sqli  GET /api/products/search  CWE-89" in section
    assert "sending" not in section
    assert markdown_section([]) == ""
    assert markdown_section(None) == ""


def test_json_report_has_no_trace():
    finding = _finding()
    raw = render("json", [finding], target="http://127.0.0.1:8000", trace=_events())
    doc = json.loads(raw)
    assert "trace" not in doc
    assert "How the scan went" not in raw
    assert doc["summary"]["high"] == 1
