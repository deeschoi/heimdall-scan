"""JWT weaknesses: guessable HMAC secret and ``alg=none`` acceptance.

Oracles (both deterministic):
  * weak secret – a candidate secret from a wordlist correctly verifies the
    target's own token signature (RFC 7519 HS256/384/512).
  * alg=none    – a forged unsigned token is accepted on a protected endpoint.

Configured via ``hints.jwt``::

    jwt:
      identity: user_a
      protected: { path: /me, method: GET }
"""

from __future__ import annotations

import base64
import json as jsonlib
import warnings

import jwt as pyjwt

from oedipus.checks import Check, ScanContext, register
from oedipus.models import Evidence, Finding, Severity

# Verifying against short lab secrets is the point; silence the length warning.
warnings.filterwarnings("ignore", module="jwt")

_DEFAULT_SECRETS = ["secret", "password", "changeme", "jwt", "key", "admin", "test"]


def _b64url_json(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    return jsonlib.loads(base64.urlsafe_b64decode(segment + pad))


@register
class JwtCheck(Check):
    id = "jwt"
    title = "Weak or forgeable JWT"
    cwe = "CWE-347"
    owasp_api = "API2:2023"
    wstg = "WSTG-SESS-10"
    asvs = "3.5.3"
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def run(self, ctx: ScanContext) -> list[Finding]:
        cfg = ctx.extras.get("jwt") or {}
        ident_name = cfg.get("identity")
        identity = None
        if ident_name:
            identity = ctx.identities.get(ident_name)
        if identity is None:
            identity = next(
                (i for i in ctx.identities.values() if i.token), None
            )
        if not identity or not identity.token:
            return []
        token = identity.token

        findings: list[Finding] = []
        weak = self._weak_secret(ctx, token)
        if weak is not None:
            findings.append(self._weak_finding(ctx, weak))

        forged = self._alg_none(ctx, token, cfg)
        if forged is not None:
            findings.append(forged)
        return findings

    # --- weak secret ---------------------------------------------------
    def _weak_secret(self, ctx: ScanContext, token: str):
        try:
            header = _b64url_json(token.split(".")[0])
        except Exception:
            return None
        alg = header.get("alg", "")
        if not alg.upper().startswith("HS"):
            return None
        for secret in ctx.load_payloads("jwt-secrets.txt") or _DEFAULT_SECRETS:
            try:
                pyjwt.decode(token, secret, algorithms=[alg])
                return secret
            except pyjwt.InvalidSignatureError:
                continue
            except pyjwt.PyJWTError:
                # expired/other, but signature verified -> still a weak secret
                try:
                    pyjwt.decode(
                        token, secret, algorithms=[alg],
                        options={"verify_exp": False, "verify_aud": False},
                    )
                    return secret
                except pyjwt.InvalidSignatureError:
                    continue
                except pyjwt.PyJWTError:
                    return secret
        return None

    def _weak_finding(self, ctx: ScanContext, secret: str) -> Finding:
        ev = Evidence(
            request_method="-",
            request_url=ctx.base_url,
            matcher=f"Token signature verifies with guessable secret {secret!r}",
            note="Signature verified offline against a wordlist.",
        )
        return Finding(
            check_id=self.id,
            title="JWT signed with a weak, guessable secret",
            severity=Severity.HIGH,
            cwe=self.cwe,
            owasp_api=self.owasp_api,
            wstg=self.wstg,
            cvss_vector=self.cvss_vector,
            asvs=self.asvs,
            method="POST",
            path_template="(login)",
            url=ctx.base_url,
            description="The HMAC secret is guessable, so any token can be forged.",
            remediation="Use a long random secret from a secrets manager; rotate it.",
            evidence=[ev],
        )

    # --- alg=none ------------------------------------------------------
    def _alg_none(self, ctx: ScanContext, token: str, cfg: dict):
        protected = cfg.get("protected")
        if not protected:
            return None
        try:
            payload = _b64url_json(token.split(".")[1])
        except Exception:
            return None
        forged = pyjwt.encode(payload, key="", algorithm="none")
        url = ctx.url(protected["path"])
        headers = {"Authorization": f"Bearer {forged}"}
        try:
            resp = ctx.client.request(
                protected.get("method", "GET"), url, headers=headers
            )
        except Exception:
            return None
        if resp.status_code >= 400:
            return None
        ev = ctx.client.evidence_from(
            resp, matcher=f"alg=none token accepted (HTTP {resp.status_code})"
        )
        return Finding(
            check_id=self.id,
            title="JWT 'alg=none' accepted on a protected endpoint",
            severity=Severity.CRITICAL,
            cwe=self.cwe,
            owasp_api=self.owasp_api,
            wstg=self.wstg,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            asvs=self.asvs,
            method=protected.get("method", "GET"),
            path_template=protected["path"],
            url=url,
            description="An unsigned token was accepted, allowing trivial impersonation.",
            remediation="Pin an allowlist of signing algorithms; reject 'none'.",
            evidence=[ev],
        )
