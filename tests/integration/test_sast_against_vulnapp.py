"""Regression for the SAST layer against Heimdall's own vulnerable app.

Unlike ``test_against_vulnapp.py`` this needs no running server: Semgrep
scans ``vulnapp/app.py`` as source. Auto-skips if the real ``semgrep`` binary
isn't on PATH (``pip install -e ".[sast]"``), so the unit suite stays green
on a bare checkout.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("semgrep", reason="sast extra not installed")
if shutil.which("semgrep") is None:
    pytest.skip("semgrep binary not on PATH", allow_module_level=True)

from heimdall.sast import scan_source  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "semgrep-rules"
SRC = ROOT / "vulnapp"

# One rule hit per planted, statically-visible bug. BOLA and excessive data
# exposure are intentionally absent -- see heimdall/sast/__init__.py's
# docstring for why those two are DAST-only.
_EXPECTED_CWES = {"CWE-89", "CWE-347", "CWE-915", "CWE-918"}


def test_sast_finds_every_statically_visible_planted_bug():
    findings = scan_source(str(RULES), str(SRC))
    assert {f.cwe for f in findings} == _EXPECTED_CWES


def test_mass_assignment_hit_resolves_to_the_register_route():
    findings = scan_source(str(RULES), str(SRC))
    hit = next(f for f in findings if f.cwe == "CWE-915")
    assert (hit.method, hit.path_template) == ("POST", "/api/register")


def test_sqli_hit_resolves_to_the_search_route():
    findings = scan_source(str(RULES), str(SRC))
    hit = next(f for f in findings if f.cwe == "CWE-89")
    assert (hit.method, hit.path_template) == ("GET", "/api/products/search")
