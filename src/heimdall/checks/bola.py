"""Broken Object Level Authorization (BOLA / IDOR).

Oracle: identity A owns an object carrying a secret canary; identity B requests
that same object and the canary leaks in B's response. Because B never had
access, any appearance of A's canary is a proven authorization break.

Configured per suite via ``hints.bola`` so the check stays target-agnostic::

    bola:
      - create: { path: /books/v1, method: POST, as: user_a,
                  json: { book_title: "heimdall_bola_book", secret: "HEIMDALL_CANARY_7f3a" } }
        read:   { path: /books/v1/heimdall_bola_book, method: GET, as: user_b }
        canary: "HEIMDALL_CANARY_7f3a"
"""

from __future__ import annotations

from heimdall.checks import Check, ScanContext, register
from heimdall.models import Finding, Severity


@register
class BolaCheck(Check):
    id = "bola"
    title = "Broken object level authorization (IDOR)"
    cwe = "CWE-639"
    owasp_api = "API1:2023"
    wstg = "WSTG-ATHZ-04"
    asvs = "4.2.1"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"

    def run(self, ctx: ScanContext) -> list[Finding]:
        specs = ctx.extras.get("bola") or []
        findings: list[Finding] = []
        for spec in specs:
            f = self._probe(ctx, spec)
            if f:
                findings.append(f)
        return findings

    def replay(self, finding: Finding, ctx: ScanContext) -> bool:
        """Re-issue the cross-tenant read and confirm the canary still leaks."""
        if not finding.evidence:
            return False
        ev = finding.evidence[0]
        canary = ev.note.split("canary=", 1)[-1] if "canary=" in ev.note else None
        resp = ctx.client.request(
            ev.request_method, ev.request_url, headers=ev.request_headers,
            allow_destructive=True,
        )
        return bool(canary and canary in (resp.text or ""))

    def _probe(self, ctx: ScanContext, spec: dict):
        canary = spec["canary"]
        create = spec.get("create")
        read = spec["read"]

        # Set up the object as the owner (idempotent enough for a lab).
        if create:
            owner = ctx.identities.get(create.get("as", "anon"))
            try:
                ctx.client.request(
                    create.get("method", "POST"),
                    ctx.url(create["path"]),
                    headers=owner.apply() if owner else None,
                    json=create.get("json"),
                    allow_destructive=True,
                )
            except Exception:
                pass

        attacker = ctx.identities.get(read.get("as", "anon"))
        read_url = ctx.url(read["path"])
        try:
            resp = ctx.client.request(
                read.get("method", "GET"),
                read_url,
                headers=attacker.apply() if attacker else None,
            )
        except Exception:
            return None

        if canary not in (resp.text or ""):
            return None

        ev = ctx.client.evidence_from(
            resp,
            matcher=f"Cross-tenant canary {canary!r} leaked to identity {read.get('as')!r}",
            note=f"canary={canary}",
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
            method=read.get("method", "GET"),
            path_template=read.get("path_template", read["path"]),
            url=read_url,
            description=(
                "An object owned by one principal was readable by another; the "
                "server performs no object-level ownership check."
            ),
            remediation="Enforce per-object ownership checks on every read/write path.",
            evidence=[ev],
        )
