"""Untrusted text cannot drive the terminal or restructure Markdown (Phase 3).

Covers F10, F15/F38, F16, F19, F20, F21, F23, F24: response bodies, spec paths,
route strings and report fields reach the operator's terminal and the Markdown
report, so they must arrive escaped.
"""

import io
import json
import re

from click.testing import CliRunner
from rich.console import Console

from heimdall.checks import TraceEvent
from heimdall.cli import main
from heimdall.correlate import correlate, render_markdown
from heimdall.models import Evidence, Finding, Severity
from heimdall.report import render
from heimdall.report.safe_text import md_code, md_fence, md_text, terminal_safe
from heimdall.report.trace import TraceLog, format_plain

ESC_PAYLOAD = "\x1b[1A\x1b[2K\x1b]52;c;ZWNobyBwd24=\x1b\\\x9b2J‮"
FENCE_BREAK = 'leak {"password":"x"}\n```\n**No issues found.**\n<!--'


def _finding(path="/p", body="", title="Excessive data exposure"):
    return Finding(
        check_id="exposure",
        title=title,
        severity=Severity.HIGH,
        cwe="CWE-213",
        owasp_api="API3:2023",
        wstg="WSTG-INFO-05",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        method="GET",
        path_template=path,
        url="http://127.0.0.1:8000" + path,
        evidence=[
            Evidence(
                request_method="GET",
                request_url="http://127.0.0.1:8000" + path,
                response_status=200,
                response_body_excerpt=body,
                matcher="sensitive key",
            )
        ],
    )


# --- helpers ---------------------------------------------------------------

def test_terminal_safe_escapes_c0_c1_and_bidi_but_keeps_newlines():
    out = terminal_safe("a\x1b[2Kb\x9bc‮d\n\te\x07")
    assert "\x1b" not in out and "\x9b" not in out and "‮" not in out
    assert "\\x1b" in out and "\\x9b" in out and "\\u202e" in out
    assert "\n\te" in out and "\x07" not in out


def test_md_code_survives_backticks_and_pipes():
    span = md_code("GET /a`b|c", in_table=True)
    assert span.startswith("``") and span.endswith("``")
    assert "\\|" in span


def test_md_fence_is_longer_than_any_backtick_run():
    lines = md_fence("x\n````\ny")
    assert lines[0] == "`````" and lines[-1] == "`````"


def test_md_text_neutralises_html():
    assert md_text("<!-- hide -->") == "&lt;!-- hide --&gt;"


# --- Markdown report (F21) -------------------------------------------------

def _visible_sections(md: str) -> list[str]:
    """Finding headings that a renderer would show (not inside a code block)."""
    shown, fence = [], None
    for line in md.splitlines():
        m = re.match(r"^(`{3,})", line)
        if m:
            if fence is None:
                fence = m.group(1)
            elif m.group(1) == fence:
                fence = None
            continue
        if fence is None and line.startswith("## "):
            shown.append(line)
    return shown


def test_response_body_cannot_close_the_evidence_fence():
    findings = [_finding(body=FENCE_BREAK), _finding(path="/second", title="Second")]
    md = render("md", findings, target="http://127.0.0.1:8000")
    assert any("Second" in h for h in _visible_sections(md))
    # The body is inside a fence longer than its own ``` line.
    assert "````" in md
    assert "<!--" in md  # literal inside the code block, not raw HTML outside it
    outside = []
    fence = None
    for line in md.splitlines():
        m = re.match(r"^(`{3,})", line)
        if m:
            fence = None if fence == m.group(1) else (fence or m.group(1))
            continue
        if fence is None:
            outside.append(line)
    assert not any("<!--" in l for l in outside)
    assert "**No issues found.**" not in outside


def test_spec_path_cannot_split_the_summary_table():
    md = render("md", [_finding(path="/a|b`c")], target="t")
    row = next(l for l in md.splitlines() if l.startswith("| HIGH"))
    # 6 columns -> 7 unescaped pipes.
    assert len(re.findall(r"(?<!\\)\|", row)) == 7


def test_markdown_report_carries_no_raw_escape_sequences():
    md = render("md", [_finding(path="/p" + ESC_PAYLOAD, body=ESC_PAYLOAD)], target="t")
    assert "\x1b" not in md and "\x9b" not in md and "‮" not in md


# --- transcript (F15, F38) -------------------------------------------------

def test_trace_prints_and_formats_target_text_escaped():
    buf = io.StringIO()
    log = TraceLog(Console(file=buf, force_terminal=True, width=200))
    finding = _finding(path="/p" + ESC_PAYLOAD)
    log(TraceEvent(check_id="exposure", kind="check", text="exposure"))
    log(TraceEvent(check_id="exposure", kind="step", text="GET /p" + ESC_PAYLOAD))
    log(TraceEvent(check_id="exposure", kind="hit", text="x", finding=finding))
    printed = buf.getvalue()
    # Rich adds its own style codes; none of ours may get through.
    assert "\x1b[1A" not in printed and "\x1b]52" not in printed
    assert "\x9b" not in printed
    plain = format_plain(log.events)
    assert "\x1b" not in plain and "\\x1b" in plain


# --- CLI print paths (F10, F16, F19, F20, F24) -----------------------------

def _write_report(tmp_path, findings):
    p = tmp_path / "r.json"
    p.write_text(render("json", findings, target="t"), encoding="utf-8")
    return str(p)


def test_gate_md_prints_markup_and_escapes_literally(tmp_path):
    report = _write_report(tmp_path, [_finding(path="/x[conceal]" + ESC_PAYLOAD, body="[link=https://evil]x[/link]")])
    result = CliRunner().invoke(main, ["gate", report, "--format", "md"])
    assert result.exit_code == 0, result.output
    assert "[conceal]" in result.output
    assert "[link=https://evil]" in result.output
    assert "\x1b[1A" not in result.output


def test_correlate_md_escapes_report_fields(tmp_path):
    dast = _finding(path="/x" + ESC_PAYLOAD)
    sast = _finding(path="/y")
    md = render_markdown(correlate([dast], [sast]))
    assert "\x1b" not in md
    d = _write_report(tmp_path, [dast])
    (tmp_path / "s.json").write_text(render("json", [sast], target="s"))
    result = CliRunner().invoke(main, ["correlate", "--dast", d, "--sast", str(tmp_path / "s.json")])
    assert result.exit_code == 0, result.output
    assert "\x1b[1A" not in result.output


def test_sast_md_output_is_printed_without_markup(tmp_path, monkeypatch):
    import heimdall.sast as sast

    route_finding = _finding(path="/x[/]" + ESC_PAYLOAD)
    monkeypatch.setattr(sast, "scan_source", lambda rules, src: [route_finding])
    (tmp_path / "rules").mkdir()
    result = CliRunner().invoke(
        main, ["sast", "--rules", str(tmp_path / "rules"), "--src", str(tmp_path)]
    )
    # An unmatched [/] would raise MarkupError if markup were on.
    assert result.exit_code == 0, result.output
    assert "[/]" in result.output
    assert "\x1b[1A" not in result.output


def test_eval_unexpected_keys_are_printed_escaped():
    from heimdall.cli import _print_eval
    from heimdall.eval.harness import EvalResult
    import heimdall.cli as cli

    buf = io.StringIO()
    cli_err, cli_console = cli.err, cli.console
    cli.err = Console(file=buf, width=200)
    cli.console = Console(file=io.StringIO())
    try:
        _print_eval(EvalResult(suite="s", tp=0, fp=1, fn=0, matched=[], missed=[],
                               unexpected=["exposure|GET|/x[red]FAKE[/red]" + ESC_PAYLOAD]))
    finally:
        cli.err, cli.console = cli_err, cli_console
    out = buf.getvalue()
    assert "[red]FAKE[/red]" in out
    assert "\x1b[1A" not in out
