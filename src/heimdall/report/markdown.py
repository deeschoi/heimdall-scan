"""Markdown reporter — human-facing report with an evidence pack per finding.

Every value that can come from the scanned target (response bodies, spec
paths, URLs) or from a report file someone else wrote goes through
:mod:`heimdall.report.safe_text`, so it cannot close a code fence, add raw
HTML, split a table cell, or carry terminal escape sequences.
"""

from __future__ import annotations

from typing import Optional

from heimdall.checks import TraceEvent
from heimdall.models import Finding, Severity
from heimdall.report.safe_text import md_code, md_fence, md_text
from heimdall.report.trace import markdown_section

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render(
    findings: list[Finding],
    target: str = "",
    trace: Optional[list[TraceEvent]] = None,
) -> str:
    lines: list[str] = []
    lines.append("# Heimdall scan report")
    lines.append("")
    lines.append(f"**Target:** {md_code(target)}  ")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")
    section = markdown_section(trace)
    if section:
        lines.append(section.rstrip("\n"))
        lines.append("")
    lines.append("| Severity | Check | Endpoint | CWE | OWASP API | WSTG |")
    lines.append("|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        lines.append(
            f"| {f.severity.value.upper()} | {md_code(f.check_id, in_table=True)} | "
            f"{md_code(f'{f.method} {f.path_template}', in_table=True)} | "
            f"{md_text(f.cwe, in_table=True)} | {md_text(f.owasp_api, in_table=True)} | "
            f"{md_text(f.wstg, in_table=True)} |"
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
        f"## {f.severity.value.upper()} — {md_text(f.title)}",
        "",
        f"- **Check:** {md_code(f.check_id)} ({md_code(f.fingerprint)})",
        f"- **Endpoint:** {md_code(f'{f.method} {f.path_template}')}",
        f"- **CWE:** {md_text(f.cwe)} · **OWASP API:** {md_text(f.owasp_api)} · "
        f"**WSTG:** {md_text(f.wstg)}"
        + (f" · **ASVS:** {md_text(f.asvs)}" if f.asvs else ""),
        f"- **CVSS 3.1:** {md_code(f.cvss_vector)}",
        "",
        md_text(f.description),
        "",
        f"**Remediation:** {md_text(f.remediation)}",
        "",
    ]
    for i, ev in enumerate(f.evidence, 1):
        out.append(f"<details><summary>Evidence #{i}: {md_text(ev.matcher)}</summary>")
        out.append("")
        request = f"{ev.request_method} {ev.request_url}"
        if ev.request_body:
            request += "\n\n" + ev.request_body[:600]
        out.extend(md_fence(request, "http"))
        out.append("")
        out.append(f"Response: {md_code(f'HTTP {ev.response_status}')}")
        out.append("")
        out.extend(md_fence((ev.response_body_excerpt or "")[:600]))
        out.append("</details>")
        out.append("")
    return out
