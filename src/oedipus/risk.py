"""Accepted-risk register and post-scan gating.

``accepted-risk.yml`` is the vuln-management ledger: a finding fingerprint, an
owner, and an expiry. Active (non-expired) entries are dropped before
``--fail-on`` so planted / accepted issues don't fail CI, while anything new
or past its deadline still does.

Consumed by ``oedipus scan --accepted-risk`` and ``oedipus gate``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml

from oedipus.models import Finding, Severity

_FP_LEN = 12


class RiskRegisterError(ValueError):
    """Invalid accepted-risk.yml."""


@dataclass(frozen=True)
class AcceptedEntry:
    fingerprint: str
    owner: str
    expiry: date
    reason: str = ""

    def is_active(self, today: Optional[date] = None) -> bool:
        return self.expiry >= (today or date.today())


@dataclass
class FilterStats:
    suppressed: list[Finding] = field(default_factory=list)
    expired_hits: list[Finding] = field(default_factory=list)
    unknown_fingerprints: list[str] = field(default_factory=list)


@dataclass
class RiskRegister:
    entries: list[AcceptedEntry]
    source: Optional[Path] = None

    def by_fingerprint(self) -> dict[str, AcceptedEntry]:
        return {e.fingerprint: e for e in self.entries}

    def partition(
        self, findings: list[Finding], *, today: Optional[date] = None
    ) -> tuple[list[Finding], FilterStats]:
        """Split findings into (kept, stats). Expired entries do not suppress."""
        today = today or date.today()
        index = self.by_fingerprint()
        kept: list[Finding] = []
        stats = FilterStats()
        seen: set[str] = set()
        for f in findings:
            seen.add(f.fingerprint)
            entry = index.get(f.fingerprint)
            if entry is None:
                kept.append(f)
                continue
            if entry.is_active(today):
                stats.suppressed.append(f)
            else:
                stats.expired_hits.append(f)
                kept.append(f)
        stats.unknown_fingerprints = [
            e.fingerprint for e in self.entries if e.fingerprint not in seen
        ]
        return kept, stats


def load_register(path: Path | str) -> RiskRegister:
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RiskRegisterError(f"accepted-risk file not found: {p}") from exc
    except yaml.YAMLError as exc:
        raise RiskRegisterError(f"invalid YAML in {p}: {exc}") from exc
    if raw is None:
        return RiskRegister(entries=[], source=p)
    if not isinstance(raw, dict):
        raise RiskRegisterError(f"{p}: expected a mapping at the top level")
    rows = raw.get("accepted", [])
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise RiskRegisterError(f"{p}: 'accepted' must be a list")
    entries: list[AcceptedEntry] = []
    seen: set[str] = set()
    for i, row in enumerate(rows):
        entries.append(_parse_entry(row, index=i, source=p, seen=seen))
    return RiskRegister(entries=entries, source=p)


def apply_filters(
    findings: list[Finding],
    *,
    accepted_risk: Optional[Path | str] = None,
    baseline: Optional[Path | str] = None,
    today: Optional[date] = None,
) -> tuple[list[Finding], FilterStats]:
    """Drop accepted-risk matches, then anything already in a baseline JSON report."""
    stats = FilterStats()
    if accepted_risk is not None:
        kept, stats = load_register(accepted_risk).partition(findings, today=today)
        findings = kept
    if baseline is not None:
        findings = diff_baseline(findings, Path(baseline))
    return findings, stats


def diff_baseline(findings: list[Finding], baseline_path: Path) -> list[Finding]:
    """Keep findings whose fingerprint is not in a prior JSON report."""
    import json

    doc = json.loads(baseline_path.read_text(encoding="utf-8"))
    rows = doc.get("findings", doc if isinstance(doc, list) else [])
    prior = {r.get("fingerprint") for r in rows if isinstance(r, dict)}
    return [f for f in findings if f.fingerprint not in prior]


def fail_on(findings: list[Finding], threshold: str) -> bool:
    """True when any finding is at/above the named severity."""
    rank = Severity(threshold).rank
    return any(f.severity.rank >= rank for f in findings)


def _parse_entry(row: object, *, index: int, source: Path, seen: set[str]) -> AcceptedEntry:
    loc = f"{source}: accepted[{index}]"
    if not isinstance(row, dict):
        raise RiskRegisterError(f"{loc}: each entry must be a mapping")
    fingerprint = str(row.get("fingerprint") or "").strip().lower()
    owner = str(row.get("owner") or "").strip()
    if not fingerprint:
        raise RiskRegisterError(f"{loc}: missing fingerprint")
    if len(fingerprint) != _FP_LEN or any(c not in "0123456789abcdef" for c in fingerprint):
        raise RiskRegisterError(
            f"{loc}: fingerprint must be the 12-char hex Finding.fingerprint, got {fingerprint!r}"
        )
    if fingerprint in seen:
        raise RiskRegisterError(f"{loc}: duplicate fingerprint {fingerprint}")
    if not owner:
        raise RiskRegisterError(f"{loc}: missing owner")
    if "expiry" not in row or row["expiry"] in (None, ""):
        raise RiskRegisterError(f"{loc}: missing expiry (YYYY-MM-DD)")
    seen.add(fingerprint)
    return AcceptedEntry(
        fingerprint=fingerprint,
        owner=owner,
        expiry=_parse_expiry(row["expiry"], loc=loc),
        reason=str(row.get("reason") or "").strip(),
    )


def _parse_expiry(value: object, *, loc: str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise RiskRegisterError(f"{loc}: expiry must be YYYY-MM-DD, got {value!r}") from exc
    raise RiskRegisterError(f"{loc}: expiry must be YYYY-MM-DD, got {value!r}")
