"""Check framework: a registry of pluggable, replayable detectors.

A :class:`Check` is the unit of detection. It receives a :class:`ScanContext`
(HTTP client, discovered endpoints, identities, payloads) and returns
:class:`~heimdall.models.Finding` objects. Each finding carries the evidence
needed for ``replay`` to independently re-confirm it later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from heimdall.auth import Identity
from heimdall.crawler import Endpoint
from heimdall.http_client import HttpClient
from heimdall.models import Finding
from heimdall.scope import ScopeError, url_host_port

# Headers that describe one connection, not the request. A replayed report must
# not choose them: a stored Host header would aim the request at another vhost.
_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
}


def replay_headers(headers: Optional[dict[str, str]]) -> dict[str, str]:
    """Stored evidence headers minus connection-level ones, for re-sending."""
    return {k: v for k, v in (headers or {}).items() if k.lower() not in _HOP_HEADERS}


@dataclass
class TraceEvent:
    """One line of the scan transcript.

    ``kind`` is ``check`` (engine, the check id as a header), ``step`` (what
    the check is about to try), ``miss``, or ``hit``. ``verbose`` lines are
    per-payload detail and stay out of the default transcript.
    """

    check_id: str
    kind: str
    text: str = ""
    finding: Optional[Finding] = None
    verbose: bool = False


@dataclass
class ScanContext:
    base_url: str
    client: HttpClient
    endpoints: list[Endpoint] = field(default_factory=list)
    identities: dict[str, Identity] = field(default_factory=dict)
    payloads_dir: Optional[Path] = None
    extras: dict = field(default_factory=dict)  # suite-specific hints
    on_trace: Optional[Callable[["TraceEvent"], None]] = None
    check_id: str = ""

    def url(self, path: str) -> str:
        """Join ``path`` onto the base URL; it must stay on the same authority.

        Paths come from the target's own spec and from suite hints, so a
        crafted path such as ``@other-host:2375/x`` must not be able to move
        the request to another host or port.
        """
        out = self.base_url.rstrip("/") + path
        base = urlsplit(self.base_url)
        joined = urlsplit(out)
        if (
            joined.scheme != base.scheme
            or url_host_port(out) != url_host_port(self.base_url)
            or joined.username is not None
        ):
            raise ScopeError(
                f"Refusing path {path!r}: it moves the request off {self.base_url}"
            )
        return out

    def trace(
        self,
        kind: str,
        text: str = "",
        *,
        finding: Optional[Finding] = None,
        verbose: bool = False,
    ) -> None:
        """Record a transcript line. No-op when the scan did not ask for one."""
        if self.on_trace is None:
            return
        self.on_trace(
            TraceEvent(
                check_id=self.check_id,
                kind=kind,
                text=text,
                finding=finding,
                verbose=verbose,
            )
        )

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
    spec_driven: bool = False
    hint_key: Optional[str] = None

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
            headers=replay_headers(ev.request_headers),
            content=ev.request_body,
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
    from heimdall.checks import (  # noqa: F401
        bola,
        exposure,
        jwt,
        mass_assignment,
        sqli,
        ssrf,
    )
