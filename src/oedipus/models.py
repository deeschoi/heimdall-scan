"""Core finding schema shared by every check and reporter.

The schema is deliberately small and typed so that:
- reporters (JSON, SARIF, Markdown) have one thing to serialize, and
- the eval harness can match findings to ``expected.json`` rows on
  ``(check_id, method, path_template)``.

Every field a resume reviewer looks for lives here: CWE, a CVSS 3.1 vector,
the OWASP API Top 10 category, and the WSTG test id.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @property
    def sarif_level(self) -> str:
        # SARIF only has none/note/warning/error.
        return {
            "info": "note",
            "low": "note",
            "medium": "warning",
            "high": "error",
            "critical": "error",
        }[self.value]


@dataclass
class Evidence:
    """A single request/response pair that proves the finding.

    ``replay`` re-issues ``request`` and re-runs the matcher, so this is the
    source of truth, not the prose in the report.
    """

    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_excerpt: Optional[str] = None
    matcher: str = ""  # human-readable description of what fired
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    cwe: str  # e.g. "CWE-639"
    owasp_api: str  # e.g. "API1:2023"
    wstg: str  # e.g. "WSTG-ATHZ-04"
    cvss_vector: str  # CVSS 3.1 vector string
    method: str
    path_template: str  # OpenAPI-style template, e.g. /users/v1/{username}
    url: str
    description: str = ""
    remediation: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    asvs: str = ""  # optional ASVS control id

    @property
    def fingerprint(self) -> str:
        """Stable id used to de-duplicate and to key baseline diffs."""
        raw = f"{self.check_id}|{self.method.upper()}|{self.path_template}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        return d

    def __str__(self) -> str:  # compact one-liner for terminal
        return (
            f"[{self.severity.value.upper():8}] {self.check_id:16} "
            f"{self.method:6} {self.path_template}  ({self.cwe})"
        )


def findings_to_json(findings: list[Finding], indent: int = 2) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=indent)
