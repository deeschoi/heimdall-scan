"""Heimdall command-line interface.

Commands:
  scan         run checks against a target (OpenAPI-driven), emit findings
  eval         score a suite against its frozen expected.json (P/R/F1 + FP)
  list-checks  show the registered checks and their metadata
  replay       re-confirm findings from a saved JSON report
  explain      print a finding's evidence and the matcher that fired
  gate         filter a JSON report (accepted-risk + baseline) and fail-on severity
  sast         run Semgrep's Heimdall rules over source, emit findings in the same schema
  correlate    join a SAST report and a DAST report on (method, path, CWE)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from heimdall import __version__
from heimdall.checks import all_check_ids, get_check, load_builtin_checks
from heimdall.engine import Suite, scan, scan_suite
from heimdall.eval import evaluate
from heimdall.http_client import HttpClient
from heimdall.models import Finding, Severity
from heimdall.report import render
from heimdall.risk import RiskRegisterError, apply_filters, fail_on
from heimdall.scope import Scope

console = Console()
err = Console(stderr=True)

SUITE_DIRS = [Path("benchmarks/suites"), Path.cwd() / "benchmarks" / "suites"]


def _resolve_suite(name_or_path: str) -> Suite:
    p = Path(name_or_path)
    if p.is_file():
        return Suite.load(str(p))
    for d in SUITE_DIRS:
        cand = d / f"{name_or_path}.yaml"
        if cand.exists():
            return Suite.load(str(cand))
    raise click.ClickException(f"Suite not found: {name_or_path!r}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="heimdall")
def main() -> None:
    """Heimdall — API DAST where every finding is a replayable check."""


@main.command()
@click.option("--target", help="Base URL of the target (e.g. http://127.0.0.1:5001).")
@click.option("--suite", "suite_name", help="Suite name or path; supplies target/auth/checks/hints.")
@click.option("--openapi", help="OpenAPI URL or file (defaults to <target>/openapi.json).")
@click.option("--check", "checks", multiple=True, help="Check id (repeatable). Default: all.")
@click.option("--format", "fmt", default="md", type=click.Choice(["json", "sarif", "md", "markdown"]))
@click.option("--out", type=click.Path(), help="Write report to a file instead of stdout.")
@click.option("--scope", "scope_hosts", multiple=True, help="Extra in-scope host (repeatable).")
@click.option("--i-understand", "allow_public", is_flag=True, help="Allow scanning non-private hosts.")
@click.option("--unsafe", is_flag=True, help="Permit destructive HTTP methods (PUT/DELETE/PATCH).")
@click.option("--rate-limit", default=20.0, help="Max requests/second.")
@click.option("--baseline", type=click.Path(exists=True), help="Prior JSON report; only report NEW findings.")
@click.option("--accepted-risk", type=click.Path(exists=True), help="YAML register; drop non-expired accepted findings before reporting/fail-on.")
@click.option("--fail-on", "fail_on_sev", type=click.Choice(["info", "low", "medium", "high", "critical"]), help="Exit 2 if any finding at/above this severity.")
def scan_cmd(target, suite_name, openapi, checks, fmt, out, scope_hosts, allow_public, unsafe, rate_limit, baseline, accepted_risk, fail_on_sev):
    """Scan a target and emit findings (JSON / SARIF / Markdown)."""
    load_builtin_checks()
    if suite_name:
        suite = _resolve_suite(suite_name)
        target = target or suite.target
        openapi = openapi or suite.openapi
        chosen = list(checks) or suite.checks
        findings = scan_suite(
            suite, scope_hosts=list(scope_hosts), allow_public=allow_public,
            unsafe=unsafe, rate_limit=rate_limit,
        )
    else:
        if not target:
            raise click.ClickException("Provide --target or --suite.")
        openapi = openapi or f"{target.rstrip('/')}/openapi.json"
        chosen = list(checks) or all_check_ids()
        findings = scan(
            target, chosen, openapi=openapi, scope_hosts=list(scope_hosts),
            allow_public=allow_public, unsafe=unsafe, rate_limit=rate_limit,
        )

    findings = _apply_filters(findings, accepted_risk=accepted_risk, baseline=baseline)

    report = render("md" if fmt == "markdown" else fmt, findings, target=target or "")
    if out:
        Path(out).write_text(report, encoding="utf-8")
        err.print(f"[green]Wrote {len(findings)} findings to {out}[/green]")
    else:
        console.print(report) if fmt in ("md", "markdown") else click.echo(report)

    _print_summary(findings, target)
    if fail_on_sev and fail_on(findings, fail_on_sev):
        sys.exit(2)


@main.command(name="eval")
@click.argument("suite_name")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--min-recall", type=float, help="Exit 2 if recall drops below this.")
@click.option("--max-fp", type=int, default=0, help="Exit 2 if safe-target false positives exceed this.")
def eval_cmd(suite_name, fmt, min_recall, max_fp):
    """Score a suite against its frozen expected.json."""
    suite = _resolve_suite(suite_name)
    result = evaluate(suite)
    if fmt == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        _print_eval(result)

    if min_recall is not None and result.recall < min_recall:
        err.print(f"[red]Recall {result.recall:.2f} < min {min_recall:.2f}[/red]")
        sys.exit(2)
    if result.safe_fp > max_fp:
        err.print(f"[red]Safe-target FPs {result.safe_fp} > max {max_fp}[/red]")
        sys.exit(2)


@main.command(name="list-checks")
def list_checks_cmd():
    """List registered checks and their standards mapping."""
    load_builtin_checks()
    table = Table(title="Heimdall checks")
    for col in ("id", "title", "CWE", "OWASP API", "WSTG", "ASVS"):
        table.add_column(col)
    for cid in all_check_ids():
        c = get_check(cid)
        table.add_row(c.id, c.title, c.cwe, c.owasp_api, c.wstg, c.asvs)
    console.print(table)


@main.command()
@click.argument("report", type=click.Path(exists=True))
@click.option("--scope", "scope_hosts", multiple=True)
@click.option("--i-understand", "allow_public", is_flag=True)
def replay(report, scope_hosts, allow_public):
    """Re-issue each finding's evidence request and re-run its matcher."""
    load_builtin_checks()
    findings = _load_findings(report)
    scope = Scope.from_targets([f.url for f in findings], allow_public=allow_public)
    for h in scope_hosts:
        scope.allow_hosts.add(h)
    ok = 0
    with HttpClient(scope, unsafe=True) as client:
        from heimdall.checks import ScanContext

        for f in findings:
            check = get_check(f.check_id)
            ctx = ScanContext(base_url=f.url, client=client)
            try:
                confirmed = check.replay(f, ctx)
            except NotImplementedError:
                confirmed = None
            mark = "[green]CONFIRMED[/green]" if confirmed else (
                "[yellow]NO-ORACLE[/yellow]" if confirmed is None else "[red]NOT REPRODUCED[/red]"
            )
            ok += 1 if confirmed else 0
            console.print(f"{mark}  {f.check_id:16} {f.method} {f.path_template}")
    console.print(f"\nReplayed {len(findings)} findings; {ok} reconfirmed.")


@main.command()
@click.argument("report", type=click.Path(exists=True))
@click.argument("fingerprint")
def explain(report, fingerprint):
    """Print a single finding's evidence and matcher."""
    doc = json.loads(Path(report).read_text(encoding="utf-8"))
    rows = doc.get("findings", doc if isinstance(doc, list) else [])
    match = next((r for r in rows if r.get("fingerprint", "").startswith(fingerprint)), None)
    if not match:
        raise click.ClickException(f"No finding with fingerprint {fingerprint!r}")
    console.print_json(json.dumps(match))


@main.command(name="sast")
@click.option("--rules", "rules_dir", default="semgrep-rules", type=click.Path(exists=True), help="Directory of Semgrep rule YAML files.")
@click.option("--src", "src_dir", default=".", type=click.Path(exists=True), help="Source directory to scan.")
@click.option("--format", "fmt", default="md", type=click.Choice(["json", "sarif", "md", "markdown"]))
@click.option("--out", type=click.Path(), help="Write report to a file instead of stdout.")
@click.option("--fail-on", "fail_on_sev", type=click.Choice(["info", "low", "medium", "high", "critical"]), help="Exit 2 if any finding at/above this severity.")
def sast_cmd(rules_dir, src_dir, fmt, out, fail_on_sev):
    """Run Semgrep's Heimdall rules over source and emit findings (same schema as scan)."""
    from heimdall.sast import SastError, scan_source

    try:
        findings = scan_source(rules_dir, src_dir)
    except SastError as exc:
        raise click.ClickException(str(exc)) from exc

    report = render("md" if fmt == "markdown" else fmt, findings, target=src_dir)
    if out:
        Path(out).write_text(report, encoding="utf-8")
        err.print(f"[green]Wrote {len(findings)} findings to {out}[/green]")
    else:
        console.print(report) if fmt in ("md", "markdown") else click.echo(report)

    _print_summary(findings, src_dir)
    if fail_on_sev and fail_on(findings, fail_on_sev):
        sys.exit(2)


@main.command(name="correlate")
@click.option("--dast", "dast_report", type=click.Path(exists=True), required=True, help="JSON report from `heimdall scan`.")
@click.option("--sast", "sast_report", type=click.Path(exists=True), required=True, help="JSON report from `heimdall sast`.")
@click.option("--format", "fmt", default="md", type=click.Choice(["json", "md", "markdown"]))
@click.option("--out", type=click.Path(), help="Write the correlation report to a file instead of stdout.")
def correlate_cmd(dast_report, sast_report, fmt, out):
    """Join a SAST report and a DAST report on (method, path, CWE)."""
    from heimdall.correlate import correlate, render as render_correlation

    dast_findings = _load_findings(dast_report)
    sast_findings = _load_findings(sast_report)
    result = correlate(dast_findings, sast_findings)
    rendered = render_correlation(result, "md" if fmt == "markdown" else fmt)

    if out:
        Path(out).write_text(rendered, encoding="utf-8")
        err.print(f"[green]Wrote correlation report to {out}[/green]")
    else:
        console.print(rendered) if fmt in ("md", "markdown") else click.echo(rendered)

    err.print(
        f"[bold]{len(result.correlated)} correlated[/bold], "
        f"{len(result.dast_only)} DAST-only, {len(result.sast_only)} SAST-only"
    )


@main.command(name="gate")
@click.argument("report", type=click.Path(exists=True))
@click.option("--accepted-risk", type=click.Path(exists=True), help="YAML register; drop non-expired accepted findings.")
@click.option("--baseline", type=click.Path(exists=True), help="Prior JSON report; only keep NEW findings.")
@click.option("--fail-on", "fail_on_sev", type=click.Choice(["info", "low", "medium", "high", "critical"]), help="Exit 2 if any remaining finding is at/above this severity.")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "sarif", "md", "markdown"]))
@click.option("--out", type=click.Path(), help="Write the filtered report. Default: stdout.")
def gate_cmd(report, accepted_risk, baseline, fail_on_sev, fmt, out):
    """Filter a JSON report through accepted-risk and/or a baseline, then optionally fail-on."""
    doc = json.loads(Path(report).read_text(encoding="utf-8"))
    rows = doc.get("findings", doc if isinstance(doc, list) else [])
    if not isinstance(rows, list):
        raise click.ClickException(f"{report}: expected a findings list")
    findings = [_finding_from_dict(r) for r in rows]
    target = doc.get("target", "") if isinstance(doc, dict) else ""
    findings = _apply_filters(findings, accepted_risk=accepted_risk, baseline=baseline)

    rendered = render("md" if fmt == "markdown" else fmt, findings, target=target)
    if out:
        Path(out).write_text(rendered, encoding="utf-8")
        err.print(f"[green]Wrote {len(findings)} findings to {out}[/green]")
    else:
        console.print(rendered) if fmt in ("md", "markdown") else click.echo(rendered)

    _print_summary(findings, target or None)
    if fail_on_sev and fail_on(findings, fail_on_sev):
        sys.exit(2)


# --- helpers ----------------------------------------------------------

def _print_summary(findings: list[Finding], target: Optional[str]) -> None:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [f"{k}={v}" for k, v in sorted(counts.items())]
    err.print(f"[bold]{len(findings)} findings[/bold] " + ("(" + ", ".join(parts) + ")" if parts else ""))


def _print_eval(r) -> None:
    table = Table(title=f"eval: {r.suite}")
    for col in ("metric", "value"):
        table.add_column(col)
    table.add_row("precision", f"{r.precision:.3f}")
    table.add_row("recall", f"{r.recall:.3f}")
    table.add_row("f1", f"{r.f1:.3f}")
    table.add_row("TP / FP / FN", f"{r.tp} / {r.fp} / {r.fn}")
    table.add_row("safe-target FPs", str(r.safe_fp))
    console.print(table)
    if r.missed:
        err.print("[yellow]Missed (false negatives):[/yellow]")
        for m in r.missed:
            err.print(f"  - {m['id']}: {m['endpoint']} ({m['check']})")
    if r.unexpected:
        err.print("[yellow]Unexpected findings (not in ground truth):[/yellow]")
        for u in r.unexpected:
            err.print(f"  - {u}")


def _apply_filters(findings: list[Finding], *, accepted_risk, baseline) -> list[Finding]:
    try:
        findings, stats = apply_filters(
            findings, accepted_risk=accepted_risk, baseline=baseline
        )
    except RiskRegisterError as exc:
        raise click.ClickException(str(exc)) from exc
    if stats.suppressed:
        err.print(f"[dim]Suppressed {len(stats.suppressed)} accepted-risk finding(s)[/dim]")
    if stats.expired_hits:
        err.print(
            f"[yellow]{len(stats.expired_hits)} finding(s) match expired accepted-risk "
            "entries; not suppressed[/yellow]"
        )
    return findings


def _load_findings(report_path: str) -> list[Finding]:
    doc = json.loads(Path(report_path).read_text(encoding="utf-8"))
    rows = doc.get("findings", doc if isinstance(doc, list) else [])
    if not isinstance(rows, list):
        raise click.ClickException(f"{report_path}: expected a findings list")
    return [_finding_from_dict(r) for r in rows]


def _finding_from_dict(d: dict) -> Finding:
    from heimdall.models import Evidence

    return Finding(
        check_id=d["check_id"],
        title=d.get("title", ""),
        severity=Severity(d.get("severity", "info")),
        cwe=d.get("cwe", ""),
        owasp_api=d.get("owasp_api", ""),
        wstg=d.get("wstg", ""),
        cvss_vector=d.get("cvss_vector", ""),
        asvs=d.get("asvs", ""),
        method=d.get("method", "GET"),
        path_template=d.get("path_template", "/"),
        url=d.get("url", ""),
        description=d.get("description", ""),
        remediation=d.get("remediation", ""),
        evidence=[Evidence(**e) for e in d.get("evidence", [])],
    )


# click renames commands with underscores; expose the intended names.
main.add_command(scan_cmd, name="scan")

if __name__ == "__main__":
    main()
