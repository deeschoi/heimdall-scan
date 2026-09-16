"""Excessive data exposure / debug endpoints.

Oracle: request GET endpoints that take no required object id and look for
sensitive fields (passwords, tokens, secrets) leaking in the response body.
Catches classic "debug" dumps like VAmPI's ``/users/v1/_debug``.
"""

from __future__ import annotations

import json as jsonlib
import re

from heimdall.checks import Check, ScanContext, register
from heimdall.crawler import fill_path
from heimdall.models import Finding, Severity

_SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "ssn", "credit_card", "cvv"}
_SENSITIVE_KEY_RE = re.compile(
    r'"(password|passwd|pwd|secret|token|ssn|credit_card|cvv)"\s*:', re.IGNORECASE
)


@register
class ExposureCheck(Check):
    id = "exposure"
    title = "Excessive data exposure of sensitive fields"
    cwe = "CWE-200"
    owasp_api = "API3:2023"
    wstg = "WSTG-ATHZ-04"
    asvs = "8.3.4"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if ep.method != "GET":
                continue
            if any(p.required for p in ep.path_params):
                # Endpoints keyed by an object id are covered by BOLA, not here.
                continue
            path_vals = {p.name: "1" for p in ep.path_params}
            url = ctx.url(fill_path(ep.path_template, path_vals))
            try:
                resp = ctx.client.request("GET", url)
            except Exception:
                continue
            if resp.status_code >= 400:
                continue
            leaked = self._leaked_keys(resp.text)
            if not leaked:
                continue
            ev = ctx.client.evidence_from(
                resp, matcher=f"Response exposes sensitive field(s): {sorted(leaked)}"
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    cwe=self.cwe,
                    owasp_api=self.owasp_api,
                    wstg=self.wstg,
                    cvss_vector=self.cvss_vector,
                    asvs=self.asvs,
                    method=ep.method,
                    path_template=ep.path_template,
                    url=url,
                    description=(
                        "The endpoint returns object fields that should never be "
                        f"serialized to clients: {sorted(leaked)}."
                    ),
                    remediation="Return an explicit response schema; strip secrets server-side.",
                    evidence=[ev],
                )
            )
        return findings

    @staticmethod
    def _leaked_keys(body: str) -> set[str]:
        found: set[str] = set()
        # Prefer structured parsing; fall back to regex for non-JSON bodies.
        try:
            data = jsonlib.loads(body)
            stack = [data]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    for k, v in cur.items():
                        if k.lower() in _SENSITIVE_KEYS and v not in (None, "", []):
                            found.add(k.lower())
                        stack.append(v)
                elif isinstance(cur, list):
                    stack.extend(cur)
        except Exception:
            found = {m.group(1).lower() for m in _SENSITIVE_KEY_RE.finditer(body or "")}
        return found

    def oracle(self, status: int, body: str) -> bool:
        return status < 400 and bool(self._leaked_keys(body))
