"""Live scan transcript and the Markdown lead-in built from the same events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

from heimdall.checks import TraceEvent
from heimdall.report.safe_text import md_fence, one_line

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
}


def visible(events: list[TraceEvent], *, verbose: bool) -> list[TraceEvent]:
    if verbose:
        return list(events)
    return [event for event in events if not event.verbose]


def _hit_line(finding) -> str:
    return one_line(
        f"  [{finding.severity.value.upper()}] {finding.check_id}  "
        f"{finding.method} {finding.path_template}  {finding.cwe}"
    )


def format_plain(events: list[TraceEvent], *, verbose: bool = False) -> str:
    """Plain transcript. Verbose payload lines are omitted unless asked for.

    Event text and finding fields can come from the scanned target (spec
    paths, token headers), so control characters are escaped.
    """
    lines: list[str] = []
    for event in visible(events, verbose=verbose):
        if event.kind == "check":
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(one_line(event.check_id))
            continue
        if event.kind == "hit" and event.finding is not None:
            lines.append(_hit_line(event.finding))
            if event.text:
                lines.append(f"        {one_line(event.text)}")
            continue
        indent = "    " if event.verbose else "  "
        lines.append(f"{indent}{one_line(event.text)}")
    return "\n".join(lines)


def markdown_section(events: Optional[list[TraceEvent]]) -> str:
    """Lead-in for the Markdown report. Always the default (non-verbose) lines."""
    body = format_plain(events or [], verbose=False).rstrip()
    if not body:
        return ""
    return "## How the scan went\n\n" + "\n".join(md_fence(body, "text")) + "\n"


@dataclass
class TraceLog:
    """Collect events and print them to stderr as they arrive."""

    console: Optional[Console] = None
    verbose: bool = False
    events: list[TraceEvent] = field(default_factory=list)
    _opened: bool = False

    def __call__(self, event: TraceEvent) -> None:
        self.events.append(event)
        if self.console is None or (event.verbose and not self.verbose):
            return
        self._print(event)

    def _print(self, event: TraceEvent) -> None:
        console = self.console
        assert console is not None
        if event.kind == "check":
            if self._opened:
                console.print()
            self._opened = True
            console.print(one_line(event.check_id), style="bold", markup=False, highlight=False)
            return
        if event.kind == "hit" and event.finding is not None:
            finding = event.finding
            style = _SEVERITY_STYLE.get(finding.severity.value, "white")
            console.print(
                _hit_line(finding),
                style=style,
                markup=False,
                highlight=False,
            )
            if event.text:
                console.print(
                    f"        {one_line(event.text)}",
                    style=style,
                    markup=False,
                    highlight=False,
                )
            return
        if event.kind == "miss":
            console.print(f"  {one_line(event.text)}", style="dim", markup=False, highlight=False)
            return
        indent = "    " if event.verbose else "  "
        console.print(f"{indent}{one_line(event.text)}", markup=False, highlight=False)
