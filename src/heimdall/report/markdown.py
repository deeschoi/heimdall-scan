"""Markdown reporter — human-facing report with an evidence pack per finding."""

from __future__ import annotations

from heimdall.models import Finding, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render(findings: list[Finding], target: str = "") -> str:
    lines: list[str] = []
    lines.append("# Heimdall scan report")
    lines.append("")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")
    lines.append("| Severity | Check | Endpoint | CWE | OWASP API | WSTG |")
    lines.append("|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        lines.append(
            f"| {f.severity.value.upper()} | `{f.check_id}` | "
            f"`{f.method} {f.path_template}` | {f.cwe} | {f.owasp_api} | {f.wstg} |"
        )
    lines.append("")

    for sev in _ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        for f in group:
            lines.extend(_finding_section(f))
    return "\n".join(lines) + "\n"


def _finding_section(f: Finding) -> list[str]:
    out = [
        f"## {f.severity.value.upper()} — {f.title}",
        "",
        f"- **Check:** `{f.check_id}` (`{f.fingerprint}`)",
        f"- **Endpoint:** `{f.method} {f.path_template}`",
        f"- **CWE:** {f.cwe} · **OWASP API:** {f.owasp_api} · **WSTG:** {f.wstg}"
        + (f" · **ASVS:** {f.asvs}" if f.asvs else ""),
        f"- **CVSS 3.1:** `{f.cvss_vector}`",
        "",
        f.description,
        "",
        f"**Remediation:** {f.remediation}",
        "",
    ]
    for i, ev in enumerate(f.evidence, 1):
        out.append(f"<details><summary>Evidence #{i}: {ev.matcher}</summary>")
        out.append("")
        out.append("```http")
        out.append(f"{ev.request_method} {ev.request_url}")
        if ev.request_body:
            out.append("")
            out.append(ev.request_body[:600])
        out.append("```")
        out.append("")
        out.append(f"Response: `HTTP {ev.response_status}`")
        out.append("")
        out.append("```")
        out.append((ev.response_body_excerpt or "")[:600])
        out.append("```")
        out.append("</details>")
        out.append("")
    return out
