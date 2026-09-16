"""SSRF oracle: prove the server really fetched an internal canary.

Two deterministic signals are under test (WSTG-INPV-19): the suite's ``match``
substring reflected back from the fetched resource, and the built-in link-local
metadata fingerprints. No timing heuristics, so an app with no fetch sink — or
one with an egress allowlist — must stay silent.
"""

import json

import httpx
import respx

from heimdall.auth import Identity
from heimdall.checks.ssrf import SsrfCheck
from heimdall.models import Severity

from .conftest import BASE

METADATA_URL = "http://169.254.169.254/latest/meta-data/"

SPEC = {
    "path": "/preview",
    "method": "POST",
    "param": "url",
    "location": "body",
    "canary": METADATA_URL,
    "match": "ami-id",
    "as": "user_a",
}


def _ctx(make_ctx, spec=SPEC):
    return make_ctx(
        identities={"user_a": Identity(name="user_a", headers={"Authorization": "Bearer A"})},
        extras={"ssrf": [spec]},
    )


@respx.mock
def test_reflected_canary_content_is_reported(make_ctx):
    route = respx.post(f"{BASE}/preview").mock(
        return_value=httpx.Response(200, text="ami-id\nami-launch-index\nhostname\n")
    )

    findings = SsrfCheck().run(_ctx(make_ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "ssrf"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-918"
    assert f.owasp_api == "API7:2023"
    assert f.method == "POST"
    assert f.path_template == "/preview"
    assert "reflected" in f.evidence[0].matcher
    assert "ami-id" in f.evidence[0].matcher
    # The canary has to actually reach the sink parameter, in the body.
    sent = json.loads(route.calls.last.request.content)
    assert sent == {"url": METADATA_URL}
    assert route.calls.last.request.headers["authorization"] == "Bearer A"


@respx.mock
def test_metadata_fingerprint_fires_without_a_configured_match(make_ctx):
    spec = {k: v for k, v in SPEC.items() if k != "match"}
    respx.post(f"{BASE}/preview").mock(
        return_value=httpx.Response(
            200, json={"body": {"AccessKeyId": "ASIAEXAMPLE", "Token": "x"}}
        )
    )

    findings = SsrfCheck().run(_ctx(make_ctx, spec))

    assert len(findings) == 1
    assert "Metadata fingerprint" in findings[0].evidence[0].matcher


@respx.mock
def test_egress_allowlist_rejection_is_silent(make_ctx):
    respx.post(f"{BASE}/preview").mock(
        return_value=httpx.Response(400, json={"detail": "host not in allowlist"})
    )

    assert SsrfCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_fetch_of_unrelated_content_is_silent(make_ctx):
    """A 200 that never proves the internal fetch happened must not fire."""
    respx.post(f"{BASE}/preview").mock(
        return_value=httpx.Response(200, json={"title": "Example Domain"})
    )

    assert SsrfCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_query_location_puts_the_canary_in_the_query_string(make_ctx):
    spec = dict(SPEC, location="query", method="GET")
    route = respx.get(f"{BASE}/preview").mock(
        return_value=httpx.Response(200, text="instance-id: i-1234")
    )

    findings = SsrfCheck().run(_ctx(make_ctx, spec))

    assert len(findings) == 1
    assert route.calls.last.request.url.params["url"] == METADATA_URL
    assert route.calls.last.request.content == b""


@respx.mock
def test_unreachable_sink_is_silent(make_ctx):
    respx.post(f"{BASE}/preview").mock(side_effect=httpx.ConnectTimeout("no route"))

    assert SsrfCheck().run(_ctx(make_ctx)) == []


def test_oracle_recognizes_metadata_signatures():
    c = SsrfCheck()
    assert c.oracle(200, "ami-id\nami-launch-index")
    assert c.oracle(200, '{"instance-id": "i-abc"}')
    assert c.oracle(200, "iam/security-credentials/ec2-role")
    assert c.oracle(200, '{"AccessKeyId": "ASIA..."}')
    assert c.oracle(200, "computeMetadata/v1/")


def test_oracle_ignores_benign_bodies():
    c = SsrfCheck()
    assert not c.oracle(200, '{"title": "Example Domain"}')
    assert not c.oracle(400, "host not in allowlist")
    assert not c.oracle(200, "")
