"""SARIF 2.1.0 reporter for GitHub Code Scanning ingest.

Each check becomes a ``rule`` (with CWE/OWASP/WSTG in properties + tags), and
each finding becomes a ``result`` whose ``ruleId`` is the check id and whose
location is the request URL. Verified against the OASIS SARIF 2.1.0 schema.
"""

from __future__ import annotations

import json

from oedipus.models import Finding

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
                "name": "oedipus",
                "informationUri": "https://github.com/dee/oedipus",
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
                    "artifactLocation": {"uri": f.url},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"oedipus/v1": f.fingerprint},
        "properties": {"cvss_vector": f.cvss_vector, "severity": f.severity.value},
    }
