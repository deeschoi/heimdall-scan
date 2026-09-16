"""SAST: run Semgrep's custom Heimdall rules and emit the shared Finding schema.

This is the static half of the "find -> prove -> patch" story: the same
``Finding`` model, reporters, and ``heimdall gate`` filters used for DAST work
unmodified on SAST hits. :mod:`heimdall.correlate` joins the two on
``(method, path_template, cwe)`` so a bug flagged by both layers becomes one
higher-confidence alert instead of two duplicate ones.

SAST here intentionally only covers what static analysis can see from source
alone (hardcoded/unverified JWT secrets, string-built SQL, a request body
field reaching an HTTP client, a privileged field on a request model). BOLA
and excessive data exposure are left to DAST: both require reasoning about
runtime state (who owns this object, what this stored dict actually
contains) that a syntactic source scan can't see.
"""

from __future__ import annotations

from typing import Any

from heimdall.models import Evidence, Finding, Severity
from heimdall.sast.routes import build_index
from heimdall.sast.runner import SastError, run_semgrep

__all__ = ["SastError", "scan_source"]

# Fills in the standards mapping (OWASP API / WSTG / CVSS) a rule's own
# metadata doesn't carry, keyed by the CWE it shares with the matching DAST
# check -- this is also what makes `heimdall correlate` line up cleanly.
_CWE_STANDARDS: dict[str, dict[str, str]] = {
    "CWE-89": {"wstg": "WSTG-INPV-05", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "CWE-918": {"wstg": "WSTG-INPV-19", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"},
    "CWE-347": {"wstg": "WSTG-SESS-10", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "CWE-915": {"wstg": "WSTG-BUSL-08", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
}

_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def scan_source(rules_dir: str, src_dir: str) -> list[Finding]:
    """Run Semgrep with ``rules_dir`` against ``src_dir``, as Finding objects."""
    results = run_semgrep(rules_dir, src_dir)
    index = build_index(src_dir)
    return [_finding_from_result(r, index) for r in results]


def _finding_from_result(result: dict[str, Any], index) -> Finding:
    rule_id = result["check_id"].rsplit(".", 1)[-1]
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    cwe = metadata.get("cwe", "CWE-0")
    standards = _CWE_STANDARDS.get(cwe, {})
    severity_name = metadata.get("heimdall_severity")
    severity = (
        Severity(severity_name)
        if severity_name in {s.value for s in Severity}
        else _SEMGREP_SEVERITY.get(extra.get("severity", "INFO"), Severity.LOW)
    )

    path = result["path"]
    line = result["start"]["line"]
    resolved = index.resolve(path, line)
    method, path_template = resolved if resolved else ("UNKNOWN", "")

    location = f"{path}:{line}"
    snippet = extra.get("lines", "").strip()

    return Finding(
        check_id=f"sast.{rule_id}",
        title=rule_id.replace("-", " ").capitalize(),
        severity=severity,
        cwe=cwe,
        owasp_api=metadata.get("owasp", ""),
        wstg=standards.get("wstg", ""),
        cvss_vector=standards.get("cvss_vector", ""),
        method=method,
        path_template=path_template,
        url=f"file://{location}",
        description=extra.get("message", ""),
        remediation=metadata.get("remediation", ""),
        evidence=[
            Evidence(
                request_method=method,
                request_url=location,
                matcher=f"semgrep:{rule_id}",
                note=snippet,
            )
        ],
    )
