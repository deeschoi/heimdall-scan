"""Live integration test against the local VAmPI benchmark.

Skips automatically if VAmPI isn't reachable, so the unit suite stays green on
machines without the lab. In CI (benchmarks/compose.yml up), this asserts that
detection does not regress: full recall and zero false positives on the safe
target.
"""

import httpx
import pytest

from heimdall.engine import Suite
from heimdall.eval import evaluate

VAMPI = "http://127.0.0.1:5001"


def _vampi_up() -> bool:
    try:
        return httpx.get(f"{VAMPI}/", timeout=2.0).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _vampi_up(), reason="VAmPI not running on :5001")


def test_vampi_full_recall_no_false_positives():
    # Seed VAmPI's DB (idempotent).
    httpx.get(f"{VAMPI}/createdb", timeout=5.0)
    httpx.get("http://127.0.0.1:5002/createdb", timeout=5.0)

    suite = Suite.load("benchmarks/suites/vampi.yaml")
    result = evaluate(suite)

    assert result.recall == 1.0, f"missed: {result.missed}"
    assert result.fp == 0, f"unexpected: {result.unexpected}"
    assert result.safe_fp == 0, f"safe-target FPs: {result.safe_findings}"
