"""Mass-assignment oracle: an injected privileged field must stick server-side.

The technique (WSTG-BUSL-08) is create-then-confirm: register a principal with a
random marker plus ``admin: true``, then read the object back. Only if the
privileged value survives the round trip is the finding reported, which is what
keeps a merely-echoed request body from becoming a false positive.
"""

import json

import httpx
import respx

from heimdall.checks.mass_assignment import MassAssignmentCheck
from heimdall.models import Severity

from .conftest import BASE

SPEC = {
    "create": {
        "path": "/users/register",
        "method": "POST",
        "base": {"username": "__RAND__", "password": "pw123", "email": "a@b.com"},
        "escalate": {"admin": True},
    },
    "confirm": {
        "path": "/users/_debug",
        "method": "GET",
        "match_field": "username",
        "privileged_field": "admin",
        "privileged_value": True,
    },
}


def _ctx(make_ctx, spec=SPEC):
    return make_ctx(extras={"mass_assignment": [spec]})


def _mock_target(*, honors_admin: bool):
    """Stand in for a register/debug pair; ``honors_admin`` plants the bug."""
    created: dict = {}

    def _register(request: httpx.Request) -> httpx.Response:
        created.update(json.loads(request.content))
        return httpx.Response(201, json={"status": "created"})

    def _debug(request: httpx.Request) -> httpx.Response:
        users = [{"username": "seed_admin", "admin": True}]
        if created:
            users.append(
                {
                    "username": created["username"],
                    "admin": bool(created.get("admin")) if honors_admin else False,
                }
            )
        return httpx.Response(200, json={"users": users})

    respx.post(f"{BASE}/users/register").mock(side_effect=_register)
    respx.get(f"{BASE}/users/_debug").mock(side_effect=_debug)
    return created


@respx.mock
def test_privileged_field_that_sticks_is_reported(make_ctx):
    created = _mock_target(honors_admin=True)

    findings = MassAssignmentCheck().run(_ctx(make_ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "mass_assignment"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-915"
    assert f.owasp_api == "API6:2023"
    assert f.method == "POST"
    assert f.path_template == "/users/register"
    # Both halves of the proof are attached: the confirm read and the create.
    assert len(f.evidence) == 2
    assert "admin=True" in f.evidence[0].matcher
    assert "{'admin': True}" in f.evidence[1].matcher
    # The injected field really was sent, alongside a fresh random marker.
    assert created["admin"] is True
    assert created["username"] not in ("__RAND__", "seed_admin")
    assert created["password"] == "pw123"


@respx.mock
def test_schema_bound_endpoint_dropping_the_field_is_silent(make_ctx):
    _mock_target(honors_admin=False)

    assert MassAssignmentCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_echoed_request_body_alone_does_not_fire(make_ctx):
    """The create response echoing ``admin: true`` proves nothing; only the read does."""

    def _register(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json=json.loads(request.content))

    respx.post(f"{BASE}/users/register").mock(side_effect=_register)
    respx.get(f"{BASE}/users/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"username": "seed", "admin": False}]})
    )

    assert MassAssignmentCheck().run(_ctx(make_ctx)) == []


@respx.mock
def test_marker_generated_per_probe(make_ctx):
    """__RAND__ must be substituted freshly so re-runs don't collide."""
    seen: list[str] = []

    def _register(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["username"])
        return httpx.Response(201)

    respx.post(f"{BASE}/users/register").mock(side_effect=_register)
    respx.get(f"{BASE}/users/_debug").mock(return_value=httpx.Response(200, json={"users": []}))

    check = MassAssignmentCheck()
    check.run(_ctx(make_ctx))
    check.run(_ctx(make_ctx))

    assert len(set(seen)) == 2


@respx.mock
def test_unreachable_confirm_step_is_silent(make_ctx):
    respx.post(f"{BASE}/users/register").mock(return_value=httpx.Response(201))
    respx.get(f"{BASE}/users/_debug").mock(side_effect=httpx.ConnectError("down"))

    assert MassAssignmentCheck().run(_ctx(make_ctx)) == []


def test_escalated_finds_the_marker_nested_in_a_list():
    confirm = SPEC["confirm"]
    body = json.dumps({"users": [{"username": "other"}, {"username": "m1", "admin": True}]})
    assert MassAssignmentCheck._escalated(body, "m1", confirm) is True


def test_escalated_requires_marker_and_value_on_the_same_object():
    confirm = SPEC["confirm"]
    body = json.dumps({"users": [{"username": "m1", "admin": False}, {"admin": True}]})
    assert MassAssignmentCheck._escalated(body, "m1", confirm) is False


def test_escalated_ignores_unknown_marker():
    confirm = SPEC["confirm"]
    body = json.dumps({"users": [{"username": "someone_else", "admin": True}]})
    assert MassAssignmentCheck._escalated(body, "m1", confirm) is False


def test_escalated_tolerates_non_json_bodies():
    confirm = SPEC["confirm"]
    assert MassAssignmentCheck._escalated("<html>500</html>", "m1", confirm) is False
