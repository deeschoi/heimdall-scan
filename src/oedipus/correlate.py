"""Join SAST and DAST findings on ``(method, path_template, cwe)``.

A bug flagged by both a static rule and a live probe is the same bug seen
from two angles — that's the "cut duplicate alerts" story: instead of a
reviewer triaging two separate tickets, ``correlate`` merges them into one
higher-confidence alert. What's left over is informative on its own:

- ``dast_only`` — proven exploitable at runtime; SAST's syntactic view either
  can't express the bug (BOLA, excessive data exposure both need semantic
  reasoning about ownership/stored state) or missed this particular shape.
- ``sast_only`` — a candidate sink or pattern in source that DAST never
  reached, confirmed, or that the guard protecting it turned out to hold at
  runtime (see the SSRF rule's docstring in ``semgrep-rules/`` for a
  concrete example of this on oedipus-vulnapp's own two url-preview routes).

Matching is deliberately coarse (method + path + CWE, not check_id) because
the SAST and DAST layers almost never share a check namespace — CWE is the
one vocabulary both a Semgrep rule and an Oedipus ``Check`` already speak.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from oedipus.models import Finding


@dataclass
class CorrelationResult:
    correlated: list[dict[str, Finding]] = field(default_factory=list)
    dast_only: list[Finding] = field(default_factory=list)
    sast_only: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "correlated": len(self.correlated),
                "dast_only": len(self.dast_only),
                "sast_only": len(self.sast_only),
            },
            "correlated": [
                {"dast": pair["dast"].to_dict(), "sast": pair["sast"].to_dict()}
                for pair in self.correlated
            ],
            "dast_only": [f.to_dict() for f in self.dast_only],
            "sast_only": [f.to_dict() for f in self.sast_only],
        }


def _key(f: Finding) -> tuple[str, str, str]:
    return (f.method.upper(), f.path_template, f.cwe)


def correlate(dast: list[Finding], sast: list[Finding]) -> CorrelationResult:
    by_key: dict[tuple[str, str, str], list[Finding]] = {}
    for f in sast:
        by_key.setdefault(_key(f), []).append(f)

    correlated: list[dict[str, Finding]] = []
    dast_only: list[Finding] = []
    matched = set()
    for d in dast:
        candidates = by_key.get(_key(d), [])
        unmatched_candidates = [s for s in candidates if id(s) not in matched]
        if unmatched_candidates:
            s = unmatched_candidates[0]
            matched.add(id(s))
            correlated.append({"dast": d, "sast": s})
        else:
            dast_only.append(d)

    sast_only = [f for f in sast if id(f) not in matched]
    return CorrelationResult(correlated=correlated, dast_only=dast_only, sast_only=sast_only)


def render_markdown(result: CorrelationResult) -> str:
    lines = [
        "# SAST + DAST correlation",
        "",
        f"- **Correlated (both layers agree):** {len(result.correlated)}",
        f"- **DAST only:** {len(result.dast_only)}",
        f"- **SAST only:** {len(result.sast_only)}",
        "",
    ]
    if result.correlated:
        lines.append("## Correlated — one alert, confirmed two ways")
        lines.append("")
        for pair in result.correlated:
            d, s = pair["dast"], pair["sast"]
            lines.append(f"### {d.method} {d.path_template} — {d.title} ({d.cwe})")
            lines.append(f"- DAST: `{d.check_id}` — {d.url}")
            lines.append(f"- SAST: `{s.check_id}` — {s.url}")
            lines.append("")
    if result.dast_only:
        lines.append("## DAST only — proven live, no matching static hit")
        lines.append("")
        for d in result.dast_only:
            lines.append(f"- `{d.check_id}` {d.method} {d.path_template} ({d.cwe}) — {d.url}")
        lines.append("")
    if result.sast_only:
        lines.append("## SAST only — static candidate, not confirmed at runtime")
        lines.append("")
        for s in result.sast_only:
            lines.append(f"- `{s.check_id}` {s.method or 'UNKNOWN'} {s.path_template or '(unresolved route)'} ({s.cwe}) — {s.url}")
        lines.append("")
    return "\n".join(lines)


def render(result: CorrelationResult, fmt: str) -> str:
    if fmt == "json":
        import json

        return json.dumps(result.to_dict(), indent=2)
    if fmt in ("md", "markdown"):
        return render_markdown(result)
    raise ValueError(f"Unknown correlate format: {fmt}")
