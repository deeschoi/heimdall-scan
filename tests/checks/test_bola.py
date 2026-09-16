"""BOLA/IDOR oracle: identity A's canary must never appear in B's response.

The detection technique under test is the cross-tenant canary read (WSTG-ATHZ-04):
plant a unique secret in an object owned by user_a, then read the same object as
user_b. Any appearance of the canary proves the server skips the ownership check.
"""

import httpx
import respx

from heimdall.auth import Identity
from heimdall.checks.bola import BolaCheck
from heimdall.models import Severity

from .conftest import BASE

CANARY = "HEIMDALL_CANARY_7f3a"

SPEC = {
    "create": {
        "path": "/invoices",
        "method": "POST",
        "as": "user_a",
        "json": {"title": "rent", "secret": CANARY},
    },
    "read": {"path": "/invoices/1", "method": "GET", "as": "user_b"},
    "canary": CANARY,
}


def _identities():
    return {
        "anon": Identity(name="anon"),
        "user_a": Identity(name="user_a", headers={"Authorization": "Bearer A"}),
        "user_b": Identity(name="user_b", headers={"Authorization": "Bearer B"}),
    }


def _ctx(make_ctx, spec=SPEC):
    return make_ctx(identities=_identities(), extras={"bola": [spec]})


@respx.mock
def test_cross_tenant_canary_leak_is_reported(make_ctx):
    create = respx.post(f"{BASE}/invoices").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    read = respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, json={"id": 1, "secret": CANARY})
    )

    findings = BolaCheck().run(_ctx(make_ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "bola"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-639"
    assert f.owasp_api == "API1:2023"
    assert f.method == "GET"
    assert f.path_template == "/invoices/1"
    assert f.url == f"{BASE}/invoices/1"
    # Evidence must carry the canary so `replay` can re-confirm it later.
    assert CANARY in f.evidence[0].matcher
    assert f.evidence[0].note == f"canary={CANARY}"
    assert f.evidence[0].response_status == 200
    assert create.called
    assert read.calls.last.request.headers["authorization"] == "Bearer B"


@respx.mock
def test_ownership_check_enforced_is_silent(make_ctx):
    respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201, json={"id": 1}))
    respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(403, json={"detail": "forbidden"})
    )

    assert BolaCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_scoped_response_without_canary_is_silent(make_ctx):
    """A 200 that only returns the attacker's *own* object must not fire."""
    respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201, json={"id": 1}))
    respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, json={"id": 1, "secret": "OTHER_TENANT_DATA"})
    )

    assert BolaCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_failed_setup_does_not_abort_the_probe(make_ctx):
    """A create step that errors is tolerated: the object may already exist."""
    respx.post(f"{BASE}/invoices").mock(side_effect=httpx.ConnectError("boom"))
    respx.get(f"{BASE}/invoices/1").mock(
        return_value=httpx.Response(200, text=f"secret={CANARY}")
    )

    assert len(BolaCheck().run(_ctx(make_ctx))) == 1


@respx.mock
def test_unreachable_target_is_silent(make_ctx):
    respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201))
    respx.get(f"{BASE}/invoices/1").mock(side_effect=httpx.ConnectError("down"))

    assert BolaCheck().run(_ctx(make_ctx)) == []


def test_spec_without_create_step_still_probes(make_ctx):
    spec = {"read": SPEC["read"], "canary": CANARY}
    with respx.mock:
        read = respx.get(f"{BASE}/invoices/1").mock(
            return_value=httpx.Response(200, text=CANARY)
        )
        findings = BolaCheck().run(_ctx(make_ctx, spec))
    assert len(findings) == 1
    assert read.call_count == 1


def test_replay_reconfirms_then_goes_quiet_once_patched(make_ctx):
    check = BolaCheck()
    ctx = _ctx(make_ctx)

    with respx.mock:
        respx.post(f"{BASE}/invoices").mock(return_value=httpx.Response(201))
        respx.get(f"{BASE}/invoices/1").mock(
            return_value=httpx.Response(200, json={"secret": CANARY})
        )
        finding = check.run(ctx)[0]
        assert check.replay(finding, ctx) is True

    # Same finding, ownership check now in place: replay must not re-confirm.
    with respx.mock:
        respx.get(f"{BASE}/invoices/1").mock(
            return_value=httpx.Response(403, json={"detail": "forbidden"})
        )
        assert check.replay(finding, ctx) is False
