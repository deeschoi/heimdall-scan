"""Evidence capture: what HttpClient records, and what it must never record.

Findings are serialized verbatim into JSON/SARIF/Markdown reports, so any
credential captured here leaks into every artifact a scan produces.
"""

import httpx
import respx

from oedipus.http_client import HttpClient
from oedipus.scope import Scope

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
        evidence = HttpClient.evidence_from(response)
    finally:
        client.close()

    names = {k.lower() for k in evidence.request_headers}
    assert "authorization" not in names
    assert "SUPERSECRET" not in str(evidence.request_headers)
    assert evidence.request_headers["x-trace-id"] == "abc123"
