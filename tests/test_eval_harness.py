"""The eval harness end to end, against a mocked target pair.

``test_eval_matching.py`` covers the match key; this covers the scoring loop:
ground-truth rows are matched, ``must_detect: false`` rows are ignored, findings
outside the ground truth count as false positives, and the ``safe_target`` run
(same checks, hardened build) is scored separately.
"""

import json

import httpx
import pytest
import respx
import yaml

from oedipus.engine import Suite
from oedipus.eval.harness import EvalResult, evaluate, load_expected

VULN = "http://127.0.0.1:8000"
SAFE = "http://127.0.0.1:8001"

SPEC = {
    "openapi": "3.0.0",
    "paths": {"/users/v1/_debug": {"get": {}}, "/notes": {"get": {}}},
}

EXPECTED = [
    {"id": "EXP-1", "check": "exposure", "method": "GET", "path": "/users/v1/_debug"},
    {"id": "EXP-2", "check": "exposure", "method": "GET", "path": "/orders"},
    {"id": "EXP-3", "check": "sqli", "method": "GET", "path": "/notes",
     "must_detect": False},
]


def _suite(tmp_path, **overrides) -> Suite:
    (tmp_path / "mock.expected.json").write_text(json.dumps(EXPECTED), encoding="utf-8")
    data = {
        "name": "mock",
        "target": VULN,
        "safe_target": SAFE,
        "openapi": f"{VULN}/openapi.json",
        "checks": ["exposure"],
        "expected": "mock.expected.json",
    }
    data.update(overrides)
    path = tmp_path / "mock.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return Suite.load(str(path))


def _mock_targets(*, safe_leaks: bool):
    for base in (VULN, SAFE):
        respx.get(f"{base}/openapi.json").mock(return_value=httpx.Response(200, json=SPEC))
    respx.get(f"{VULN}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"password": "p"}]})
    )
    # Not in the ground truth -> a false positive on the vulnerable build.
    respx.get(f"{VULN}/notes").mock(return_value=httpx.Response(200, json={"token": "t"}))
    respx.get(f"{SAFE}/users/v1/_debug").mock(
        return_value=httpx.Response(200, json={"users": [{"password": "p"}]} if safe_leaks else {})
    )
    respx.get(f"{SAFE}/notes").mock(return_value=httpx.Response(200, json={"notes": []}))


@respx.mock
def test_evaluate_scores_matches_misses_and_false_positives(tmp_path):
    _mock_targets(safe_leaks=False)

    result = evaluate(_suite(tmp_path), rate_limit=0)

    assert result.suite == "mock"
    assert result.matched == ["EXP-1"]
    assert result.tp == 1
    # EXP-2 was never detected; EXP-3 is must_detect:false so it is not scored.
    assert result.fn == 1
    assert [m["id"] for m in result.missed] == ["EXP-2"]
    assert result.missed[0]["endpoint"] == "GET /orders"
    assert result.unexpected == ["exposure|GET|/notes"]
    assert result.fp == 1
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.f1 == 0.5


@respx.mock
def test_evaluate_scores_the_hardened_build_separately(tmp_path):
    """The safe_target run reuses the suite's checks against the patched build."""
    _mock_targets(safe_leaks=True)

    result = evaluate(_suite(tmp_path), rate_limit=0)

    assert result.safe_fp == 1
    assert result.safe_findings == ["exposure|GET|/users/v1/_debug"]
    assert respx.calls.call_count  # both targets were crawled
    assert result.to_dict()["safe_target_false_positives"] == 1


@respx.mock
def test_evaluate_rewrites_the_spec_url_for_the_safe_target(tmp_path):
    _mock_targets(safe_leaks=False)

    evaluate(_suite(tmp_path), rate_limit=0)

    urls = [str(c.request.url) for c in respx.calls]
    assert f"{SAFE}/openapi.json" in urls


@respx.mock
def test_evaluate_skips_the_safe_run_when_no_safe_target(tmp_path):
    _mock_targets(safe_leaks=True)

    result = evaluate(_suite(tmp_path, safe_target=None), rate_limit=0)

    assert result.safe_fp == 0
    assert not any(str(c.request.url).startswith(SAFE) for c in respx.calls)


def test_evaluate_requires_ground_truth(tmp_path):
    suite = _suite(tmp_path, expected="nope.json")
    with pytest.raises(FileNotFoundError):
        evaluate(suite, rate_limit=0)


def test_load_expected_accepts_both_shapes(tmp_path):
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(EXPECTED), encoding="utf-8")
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"expected": EXPECTED}), encoding="utf-8")

    assert load_expected(bare) == load_expected(wrapped) == EXPECTED


def test_metrics_on_a_perfect_run():
    r = EvalResult(suite="s", tp=7, fp=0, fn=0, matched=[], missed=[], unexpected=[])
    assert (r.precision, r.recall, r.f1) == (1.0, 1.0, 1.0)


def test_metrics_when_everything_is_a_false_positive():
    r = EvalResult(suite="s", tp=0, fp=3, fn=0, matched=[], missed=[], unexpected=[])
    assert r.precision == 0.0
    assert r.recall == 1.0  # nothing was expected, so nothing was missed
    assert r.f1 == 0.0


def test_metrics_on_an_empty_scan():
    r = EvalResult(suite="s", tp=0, fp=0, fn=4, matched=[], missed=[], unexpected=[])
    assert r.precision == 1.0
    assert r.recall == 0.0
    assert r.f1 == 0.0
