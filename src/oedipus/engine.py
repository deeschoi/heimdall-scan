"""Suite loading and the scan engine that wires crawler + auth + checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from oedipus.auth import build_identities
from oedipus.checks import ScanContext, get_check, load_builtin_checks
from oedipus.crawler import load_spec, parse_endpoints
from oedipus.http_client import HttpClient
from oedipus.models import Finding
from oedipus.scope import Scope


@dataclass
class Suite:
    name: str
    target: str
    checks: list[str]
    openapi: Optional[str] = None
    safe_target: Optional[str] = None
    auth: dict[str, Any] = field(default_factory=dict)
    hints: dict[str, Any] = field(default_factory=dict)
    expected: Optional[str] = None
    payloads_dir: Optional[str] = None
    exclude: list[str] = field(default_factory=list)
    safe_checks: Optional[list[str]] = None
    _base_dir: Optional[Path] = None

    @classmethod
    def load(cls, path: str) -> "Suite":
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        return cls(
            name=data.get("name", p.stem),
            target=data["target"],
            checks=data.get("checks", []),
            openapi=data.get("openapi"),
            safe_target=data.get("safe_target"),
            auth=data.get("auth", {}),
            hints=data.get("hints", {}),
            expected=data.get("expected"),
            payloads_dir=data.get("payloads_dir"),
            exclude=data.get("exclude", []),
            safe_checks=data.get("safe_checks"),
            _base_dir=p.parent,
        )

    def resolve(self, rel: Optional[str]) -> Optional[Path]:
        if not rel:
            return None
        p = Path(rel)
        if not p.is_absolute() and self._base_dir:
            p = (self._base_dir / p).resolve()
        return p


def scan(
    target: str,
    check_ids: list[str],
    *,
    openapi: Optional[str] = None,
    auth: Optional[dict] = None,
    hints: Optional[dict] = None,
    payloads_dir: Optional[Path] = None,
    scope_hosts: Optional[list[str]] = None,
    allow_public: bool = False,
    unsafe: bool = False,
    rate_limit: float = 20.0,
    exclude: Optional[list[str]] = None,
) -> list[Finding]:
    """Run the given checks against ``target`` and return findings."""
    load_builtin_checks()
    scope = Scope.from_targets([target] + (scope_hosts or []), allow_public=allow_public)

    endpoints = []
    if openapi:
        try:
            endpoints = parse_endpoints(load_spec(openapi))
        except Exception:
            endpoints = []

    # Drop side-effecting / utility endpoints (e.g. /createdb) from the crawl so
    # crawl-based checks don't mutate the target and invalidate other checks.
    exclude = exclude or []
    if exclude:
        endpoints = [e for e in endpoints if e.path_template not in exclude]

    identities = build_identities(target, auth or {}, verify_tls=False)

    findings: list[Finding] = []
    with HttpClient(scope, rate_limit_per_sec=rate_limit, unsafe=unsafe) as client:
        ctx = ScanContext(
            base_url=target,
            client=client,
            endpoints=endpoints,
            identities=identities,
            payloads_dir=payloads_dir,
            extras=hints or {},
        )
        for cid in check_ids:
            check = get_check(cid)
            try:
                findings.extend(check.run(ctx))
            except Exception as exc:  # a broken check must not abort the scan
                import sys

                print(f"[warn] check {cid} errored: {exc}", file=sys.stderr)

    # De-duplicate on fingerprint.
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.fingerprint, f)
    return list(unique.values())


def scan_suite(suite: Suite, **overrides) -> list[Finding]:
    payloads = suite.resolve(suite.payloads_dir)
    return scan(
        suite.target,
        suite.checks,
        openapi=suite.openapi,
        auth=suite.auth,
        hints=suite.hints,
        payloads_dir=payloads,
        exclude=suite.exclude,
        **overrides,
    )
