"""End-to-end regression against Oedipus' own vulnerable app.

Boots two builds of ``vulnapp`` as real subprocesses — the vulnerable target on
:8000 and the hardened false-positive control on :8001 — then runs the full
``oedipus eval vulnapp`` and asserts:

  * every planted bug is detected (recall == 1.0),
  * nothing unexpected fires on the vulnerable target (fp == 0),
  * the hardened build produces zero findings (safe_fp == 0).

Auto-skips if FastAPI/uvicorn aren't installed (``pip install -e ".[vulnapp]"``),
so the unit suite stays green on a bare checkout.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi", reason="vulnapp extra not installed")
pytest.importorskip("uvicorn", reason="vulnapp extra not installed")

from oedipus.engine import Suite  # noqa: E402
from oedipus.eval import evaluate  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "benchmarks" / "suites" / "vulnapp.yaml"
VULN_PORT, SAFE_PORT = 8000, 8001


def _wait_up(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1.0).status_code == 200:
                return True
        except Exception:
            time.sleep(0.2)
    return False


def _boot(port: int, safe: bool) -> subprocess.Popen:
    env = dict(os.environ, PORT=str(port), VULNAPP_SAFE="1" if safe else "0")
    return subprocess.Popen(
        [sys.executable, "-m", "vulnapp"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )


@pytest.fixture(scope="module")
def vulnapp_running():
    # Don't fight a copy already bound to these ports (e.g. `make vulnapp-up`).
    already = _wait_up(VULN_PORT, timeout=1.0) and _wait_up(SAFE_PORT, timeout=1.0)
    procs: list[subprocess.Popen] = []
    if not already:
        procs = [_boot(VULN_PORT, safe=False), _boot(SAFE_PORT, safe=True)]
        if not (_wait_up(VULN_PORT) and _wait_up(SAFE_PORT)):
            for p in procs:
                p.terminate()
            pytest.skip("vulnapp did not start")
    try:
        yield
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


def test_vulnapp_full_recall_no_false_positives(vulnapp_running):
    suite = Suite.load(str(SUITE))
    result = evaluate(suite)

    assert result.recall == 1.0, f"missed: {result.missed}"
    assert result.fp == 0, f"unexpected on vulnerable build: {result.unexpected}"
    assert result.safe_fp == 0, f"false positives on hardened build: {result.safe_findings}"
    assert result.tp == 7, f"expected 7 planted bugs, matched {result.tp}"
