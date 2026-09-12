"""Check framework: a registry of pluggable, replayable detectors.

A :class:`Check` is the unit of detection. It receives a :class:`ScanContext`
(HTTP client, discovered endpoints, identities, payloads) and returns
:class:`~oedipus.models.Finding` objects. Each finding carries the evidence
needed for ``replay`` to independently re-confirm it later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from oedipus.auth import Identity
from oedipus.crawler import Endpoint
from oedipus.http_client import HttpClient
from oedipus.models import Finding


@dataclass
class ScanContext:
    base_url: str
    client: HttpClient
    endpoints: list[Endpoint] = field(default_factory=list)
    identities: dict[str, Identity] = field(default_factory=dict)
    payloads_dir: Optional[Path] = None
    extras: dict = field(default_factory=dict)  # suite-specific hints

    def url(self, path: str) -> str:
        return self.base_url.rstrip("/") + path

    def load_payloads(self, name: str) -> list[str]:
        """Load a payload file (comment lines starting with '#' are ignored)."""
        if not self.payloads_dir:
            return []
        fp = self.payloads_dir / name
        if not fp.exists():
            return []
        out = []
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out


class Check:
    """Base class. Subclasses set metadata and implement :meth:`run`."""

    id: str = "base"
    title: str = ""
    cwe: str = ""
    owasp_api: str = ""
    wstg: str = ""
    asvs: str = ""
    cvss_vector: str = ""

    def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def replay(self, finding: Finding, ctx: ScanContext) -> bool:
        """Re-issue the finding's first evidence request and re-run the oracle.

        Default implementation re-sends the request and asks the subclass to
        judge the response via :meth:`oracle`.
        """
        if not finding.evidence:
            return False
        ev = finding.evidence[0]
        resp = ctx.client.request(
            ev.request_method,
            ev.request_url,
            headers=ev.request_headers,
            content=ev.request_body,
            allow_destructive=True,
        )
        return self.oracle(resp.status_code, resp.text)

    def oracle(self, status: int, body: str) -> bool:  # pragma: no cover - optional
        """Return True if a response still demonstrates the vulnerability."""
        raise NotImplementedError


_REGISTRY: dict[str, Callable[[], Check]] = {}


def register(factory: Callable[[], Check]) -> Callable[[], Check]:
    inst = factory()
    _REGISTRY[inst.id] = factory
    return factory


def get_check(check_id: str) -> Check:
    if check_id not in _REGISTRY:
        raise KeyError(f"Unknown check: {check_id}. Known: {sorted(_REGISTRY)}")
    return _REGISTRY[check_id]()


def all_check_ids() -> list[str]:
    return sorted(_REGISTRY)


def load_builtin_checks() -> None:
    """Import built-in check modules so they self-register."""
    from oedipus.checks import (  # noqa: F401
        bola,
        exposure,
        jwt,
        mass_assignment,
        sqli,
        ssrf,
    )
