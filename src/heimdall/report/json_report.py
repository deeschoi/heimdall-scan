"""JSON reporter — the canonical machine-readable output and baseline format."""

from __future__ import annotations

import json

from heimdall.models import Finding


def render(findings: list[Finding], target: str = "") -> str:
    doc = {
        "tool": "heimdall",
        "version": "0.1.0",
        "target": target,
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2)


def _summary(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    counts["total"] = len(findings)
    return counts
