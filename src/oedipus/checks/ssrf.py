"""Server-Side Request Forgery.

Oracle: point a URL-valued parameter at an internal canary and confirm the
server actually fetched it — either by a reflected marker in the response or by
metadata-service fingerprints. No blind timing guesses, so no false positives
on apps without a fetch sink (it simply reports nothing).

Payload vectors are derived from PayloadsAllTheThings/HackTricks (redirect,
decimal IP, IPv6, link-local metadata) and live in ``payloads/ssrf.txt``.

Configured via ``hints.ssrf``::

    ssrf:
      - path: /workshop/api/merchant/contact_mechanic
        method: POST
        param: mechanic_api
        location: body            # body | query
        canary: "http://169.254.169.254/latest/meta-data/"
        match: "ami-id"           # substring proving the fetch happened
"""

from __future__ import annotations

import re

from oedipus.checks import Check, ScanContext, register
from oedipus.crawler import fill_path
from oedipus.models import Finding, Severity

# Response fingerprints of common internal/metadata endpoints.
_METADATA_SIGNS = [
    r"ami-id",
    r"instance-id",
    r"iam/security-credentials",
    r"computeMetadata",
    r"\"AccessKeyId\"",
]
_META_RE = re.compile("|".join(_METADATA_SIGNS), re.IGNORECASE)

_URL_PARAM_RE = re.compile(r"url|uri|link|callback|webhook|target|dest|redirect|fetch|host|api", re.I)


@register
class SsrfCheck(Check):
    id = "ssrf"
    title = "Server-side request forgery"
    cwe = "CWE-918"
    owasp_api = "API7:2023"
    wstg = "WSTG-INPV-19"
    asvs = "12.6.1"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for spec in ctx.extras.get("ssrf") or []:
            f = self._probe_hint(ctx, spec)
            if f:
                findings.append(f)
        return findings

    def _probe_hint(self, ctx: ScanContext, spec: dict):
        canary = spec["canary"]
        match = spec.get("match")
        param = spec["param"]
        location = spec.get("location", "body")
        url = ctx.url(spec["path"])
        identity = ctx.identities.get(spec.get("as", "anon"))
        headers = identity.apply() if identity else None
        kwargs: dict = {"headers": headers, "allow_destructive": True}
        if location == "query":
            kwargs["params"] = {param: canary}
        else:
            kwargs["json"] = {param: canary}
        try:
            resp = ctx.client.request(spec.get("method", "POST"), url, **kwargs)
        except Exception:
            return None
        body = resp.text or ""
        fired = None
        if match and match in body:
            fired = f"Injected canary reflected in response: {match!r}"
        elif _META_RE.search(body):
            fired = f"Metadata fingerprint in response: {_META_RE.search(body).group(0)!r}"
        if not fired:
            return None
        ev = ctx.client.evidence_from(resp, matcher=fired)
        return Finding(
            check_id=self.id,
            title=self.title,
            severity=Severity.HIGH,
            cwe=self.cwe,
            owasp_api=self.owasp_api,
            wstg=self.wstg,
            cvss_vector=self.cvss_vector,
            asvs=self.asvs,
            method=spec.get("method", "POST"),
            path_template=spec["path"],
            url=url,
            description="A URL parameter caused the server to fetch an attacker-controlled internal resource.",
            remediation="Validate against an egress allowlist; block link-local/RFC1918; disable redirects.",
            evidence=[ev],
        )

    def oracle(self, status: int, body: str) -> bool:
        return bool(_META_RE.search(body or ""))
