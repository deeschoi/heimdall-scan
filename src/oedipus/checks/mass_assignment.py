"""Mass assignment / BFLA-style privilege escalation.

Oracle: create an object while injecting a privileged field the client should
not control (e.g. ``admin: true``), then read the object back and confirm the
privileged value stuck. Two-step create-then-confirm keeps it deterministic.

Configured per suite via ``hints.mass_assignment`` so no target-specific code
lives in the check::

    mass_assignment:
      - create:  { path: /users/v1/register, method: POST,
                   base: { username: "__RAND__", password: "pw123", email: "a@b.com" },
                   escalate: { admin: true } }
        confirm: { path: /users/v1/_debug, method: GET,
                   match_field: username, privileged_field: admin,
                   privileged_value: true }
"""

from __future__ import annotations

import json as jsonlib
import uuid

from oedipus.checks import Check, ScanContext, register
from oedipus.models import Finding, Severity


@register
class MassAssignmentCheck(Check):
    id = "mass_assignment"
    title = "Mass assignment enables privilege escalation"
    cwe = "CWE-915"
    owasp_api = "API6:2023"
    wstg = "WSTG-BUSL-08"
    asvs = "5.1.2"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def run(self, ctx: ScanContext) -> list[Finding]:
        specs = ctx.extras.get("mass_assignment") or []
        findings: list[Finding] = []
        for spec in specs:
            f = self._probe(ctx, spec)
            if f:
                findings.append(f)
        return findings

    def _probe(self, ctx: ScanContext, spec: dict):
        create = spec["create"]
        confirm = spec["confirm"]
        rand = uuid.uuid4().hex[:10]
        base = {k: (rand if v == "__RAND__" else v) for k, v in create.get("base", {}).items()}
        payload = dict(base)
        payload.update(create.get("escalate", {}))
        marker = base.get(confirm["match_field"])

        create_url = ctx.url(create["path"])
        try:
            create_resp = ctx.client.request(
                create.get("method", "POST"), create_url, json=payload,
                allow_destructive=True,
            )
        except Exception:
            return None

        confirm_url = ctx.url(confirm["path"])
        try:
            confirm_resp = ctx.client.request(confirm.get("method", "GET"), confirm_url)
        except Exception:
            return None

        if not self._escalated(confirm_resp.text, marker, confirm):
            return None

        ev_confirm = ctx.client.evidence_from(
            confirm_resp,
            matcher=(
                f"Created principal {marker!r} shows "
                f"{confirm['privileged_field']}={confirm['privileged_value']!r}"
            ),
        )
        ev_create = ctx.client.evidence_from(
            create_resp, matcher=f"Injected privileged field via create: {create.get('escalate')}"
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
            method=create.get("method", "POST"),
            path_template=create["path"],
            url=create_url,
            description=(
                "A create endpoint honored a privileged attribute supplied by the "
                "client, allowing self-granted elevated privileges."
            ),
            remediation="Bind requests to an explicit input schema; never mass-assign models.",
            evidence=[ev_confirm, ev_create],
        )

    @staticmethod
    def _escalated(body: str, marker, confirm: dict) -> bool:
        field = confirm["privileged_field"]
        want = confirm["privileged_value"]
        match_field = confirm["match_field"]
        try:
            data = jsonlib.loads(body)
        except Exception:
            return False
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                if cur.get(match_field) == marker and cur.get(field) == want:
                    return True
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
        return False
