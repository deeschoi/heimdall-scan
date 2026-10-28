"""Suite loading and the scan engine that wires crawler + auth + checks."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from heimdall.auth import build_identities
<<<<<<< HEAD
from heimdall.checks import ScanContext, TraceEvent, get_check, load_builtin_checks
=======
from heimdall.checks import Check, ScanContext, get_check, load_builtin_checks
>>>>>>> b8462ef (Fail a scan when scope, the spec, or a destructive method blocks it.)
from heimdall.crawler import load_spec, parse_endpoints
from heimdall.http_client import HttpClient
from heimdall.models import Finding
from heimdall.scope import Scope, ScopeError


class ScanError(Exception):
    """Raised when a scan cannot proceed."""


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


def _load_endpoints(openapi: Optional[str], checks: list[Check]) -> list:
    """Load the OpenAPI document, or fail when a spec-driven check needs it."""
    needs_spec = any(c.spec_driven for c in checks)
    if not openapi:
        if needs_spec:
            raise ScanError("could not load OpenAPI spec: not provided")
        return []
    try:
        return parse_endpoints(load_spec(openapi))
    except Exception as exc:
        if needs_spec:
            raise ScanError(
                f"could not load OpenAPI spec from {openapi}: {exc}"
            ) from exc
        print(
            f"[warn] could not load OpenAPI spec from {openapi}: {exc}",
            file=sys.stderr,
        )
        return []


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
    verify_tls: bool = True,
    exclude: Optional[list[str]] = None,
    on_trace: Optional[Callable[[TraceEvent], None]] = None,
) -> list[Finding]:
    """Run the given checks against ``target`` and return findings."""
    load_builtin_checks()
    scope = Scope.from_targets([target] + (scope_hosts or []), allow_public=allow_public)
    scope.validate()
    checks = [get_check(cid) for cid in check_ids]

    endpoints = _load_endpoints(openapi, checks)

    # Drop side-effecting / utility endpoints (e.g. /createdb) from the crawl so
    # crawl-based checks don't mutate the target and invalidate other checks.
    exclude = exclude or []
    if exclude:
        endpoints = [e for e in endpoints if e.path_template not in exclude]

    findings: list[Finding] = []
    hint_map = hints or {}
    with HttpClient(
        scope, rate_limit_per_sec=rate_limit, unsafe=unsafe, verify_tls=verify_tls
    ) as client:
        identities = build_identities(target, auth or {}, client)
        ctx = ScanContext(
            base_url=target,
            client=client,
            endpoints=endpoints,
            identities=identities,
            payloads_dir=payloads_dir,
<<<<<<< HEAD
            extras=hints or {},
            on_trace=on_trace,
        )
        for cid in check_ids:
            check = get_check(cid)
            ctx.check_id = cid
            if on_trace is not None:
                on_trace(TraceEvent(check_id=cid, kind="check", text=cid))
=======
            extras=hint_map,
        )
        for cid, check in zip(check_ids, checks):
            if check.hint_key and not hint_map.get(check.hint_key):
                print(
                    f"[info] check {cid} skipped: no hints.{check.hint_key} in suite",
                    file=sys.stderr,
                )
                continue
>>>>>>> b8462ef (Fail a scan when scope, the spec, or a destructive method blocks it.)
            try:
                findings.extend(check.run(ctx))
            except ScopeError:
                raise
            except PermissionError as exc:
                print(f"[warn] check {cid} blocked: {exc}", file=sys.stderr)
            except Exception as exc:  # a broken check must not abort the scan
                print(f"[warn] check {cid} errored: {exc}", file=sys.stderr)

    # De-duplicate on fingerprint.
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.fingerprint, f)
    return list(unique.values())


def scan_suite(suite: Suite, **overrides) -> list[Finding]:
    payloads = suite.resolve(suite.payloads_dir)
    openapi = suite.openapi
    # File paths are suite-relative (same convention as expected/payloads_dir).
    # URLs are left untouched so VAmPI/vulnapp keep fetching live specs.
    if openapi and not str(openapi).startswith(("http://", "https://")):
        resolved = suite.resolve(openapi)
        openapi = str(resolved) if resolved else openapi
    return scan(
        suite.target,
        suite.checks,
        openapi=openapi,
        auth=suite.auth,
        hints=suite.hints,
        payloads_dir=payloads,
        exclude=suite.exclude,
        **overrides,
    )
