"""Error-based SQL injection.

Oracle: inject a payload known to break SQL syntax and look for a database
error signature in the response. This is deterministic (no timing heuristics)
and maps cleanly to a replayable request.
"""

from __future__ import annotations

import re

from heimdall.checks import Check, ScanContext, register
from heimdall.crawler import fill_path
from heimdall.models import Evidence, Finding, Severity

# Signatures across the common engines. Kept explicit so the oracle is auditable.
_SQL_ERROR_SIGNATURES = [
    r"sqlalchemy\.exc\.\w*Error",
    r"sqlite3\.OperationalError",
    r"unrecognized token",
    r"You have an error in your SQL syntax",
    r"psycopg2\.\w+",
    r"PG::\w+Error",
    r"ORA-\d{5}",
    r"SQLSTATE\[",
    r"Microsoft SQL Server",
    r"Unclosed quotation mark",
]
_SIG_RE = re.compile("|".join(_SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Fallback payloads if no payload file is provided.
_DEFAULT_PAYLOADS = ["'", "\"", "' OR '1'='1", "1'--"]


@register
class SqliCheck(Check):
    id = "sqli"
    title = "Error-based SQL injection"
    cwe = "CWE-89"
    owasp_api = "API8:2023"
    wstg = "WSTG-INPV-05"
    asvs = "5.3.4"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

    def run(self, ctx: ScanContext) -> list[Finding]:
        payloads = ctx.load_payloads("sqli.txt") or _DEFAULT_PAYLOADS
        findings: list[Finding] = []
        seen: set[str] = set()

        for ep in ctx.endpoints:
            if ep.method != "GET":
                continue
            # Only inject into string-ish path/query params.
            targets = [(p, "path") for p in ep.path_params] + [
                (p, "query") for p in ep.query_params
            ]
            if not targets:
                continue
            for payload in payloads:
                fired = self._probe(ctx, ep, targets, payload, seen)
                if fired:
                    findings.append(fired)
                    break  # one confirmed injection per endpoint is enough
        return findings

    def _probe(self, ctx, ep, targets, payload, seen):
        path_vals = {p.name: "1" for p in ep.path_params}
        params = {p.name: "1" for p in ep.query_params}
        for p, loc in targets:
            if loc == "path":
                path_vals[p.name] = payload
            else:
                params[p.name] = payload
        url = ctx.url(fill_path(ep.path_template, path_vals))
        try:
            resp = ctx.client.request("GET", url, params=params or None)
        except Exception:
            return None
        m = _SIG_RE.search(resp.text or "")
        if not m:
            return None
        key = f"{ep.method}:{ep.path_template}"
        if key in seen:
            return None
        seen.add(key)
        ev = ctx.client.evidence_from(
            resp, matcher=f"SQL error signature: {m.group(0)!r} (payload={payload!r})"
        )
        return Finding(
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
                "A database error was returned when injecting SQL metacharacters, "
                "indicating unsanitized input is concatenated into a query."
            ),
            remediation="Use parameterized queries / an ORM binding; never string-format SQL.",
            evidence=[ev],
        )

    def oracle(self, status: int, body: str) -> bool:
        return bool(_SIG_RE.search(body or ""))
