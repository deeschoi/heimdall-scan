"""SARIF 2.1.0 reporter for GitHub Code Scanning ingest.

Each check becomes a ``rule`` (with CWE/OWASP/WSTG in properties + tags), and
each finding becomes a ``result`` whose ``ruleId`` is the check id.

DAST findings live at HTTP endpoints, not source files. GitHub Code Scanning
rejects ``physicalLocation`` URIs whose scheme is ``http``/``https`` (checkout
is ``file``), and its ingest API also *requires* a ``physicalLocation`` on
every result — a location with only ``logicalLocations`` is rejected with
"expected a physical location". So each result gets both: a synthetic
repo-relative ``physicalLocation`` (satisfies ingest; no snippet is expected
since the file doesn't exist) and a ``logicalLocations`` entry carrying the
real endpoint identity. The request URL stays in the message and properties.
"""

from __future__ import annotations

import json
import re

from heimdall.models import Finding


def _synthetic_artifact_uri(f: Finding) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", f.path_template).strip("-").lower() or "root"
    return f"heimdall-findings/{f.check_id}/{f.method.lower()}-{slug}.dast"

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render(findings: list[Finding], target: str = "") -> str:
    rules_by_id: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.check_id not in rules_by_id:
            rules_by_id[f.check_id] = _rule(f)
        results.append(_result(f))

    run = {
        "tool": {
            "driver": {
                "name": "heimdall",
                "informationUri": "https://github.com/dee/heimdall",
                "version": "0.1.0",
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }
    doc = {"version": SARIF_VERSION, "$schema": SCHEMA, "runs": [run]}
    return json.dumps(doc, indent=2)


def _rule(f: Finding) -> dict:
    return {
        "id": f.check_id,
        "name": f.check_id.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.description or f.title},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
        "properties": {
            "cwe": f.cwe,
            "owasp_api": f.owasp_api,
            "wstg": f.wstg,
            "asvs": f.asvs,
            "tags": ["security", f.cwe, f.owasp_api],
        },
        "defaultConfiguration": {"level": f.severity.sarif_level},
    }


def _result(f: Finding) -> dict:
    return {
        "ruleId": f.check_id,
        "level": f.severity.sarif_level,
        "message": {
            "text": f"{f.title} at {f.method} {f.path_template} ({f.cwe}, {f.owasp_api})."
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _synthetic_artifact_uri(f)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "name": f"{f.method} {f.path_template}",
                        "fullyQualifiedName": f.url,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {"heimdall/v1": f.fingerprint},
        "properties": {
            "cvss_vector": f.cvss_vector,
            "severity": f.severity.value,
            "url": f.url,
            "method": f.method,
            "path_template": f.path_template,
        },
    }
