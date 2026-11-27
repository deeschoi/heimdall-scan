"""`heimdall replay` only contacts hosts the operator names (F12).

A report is a data file -- shared, uploaded as a CI artifact, committed -- so
nothing in it may choose where replay sends requests, which methods it uses,
or which Host header it carries.
"""

import json

import httpx
import respx
from click.testing import CliRunner

from heimdall.cli import main

BASE = "http://127.0.0.1:8000"


def _report(tmp_path, *, url, ev_url, method="GET", headers=None, check="exposure"):
    doc = {
        "target": url,
        "findings": [
            {
                "check_id": check,
                "title": "t",
                "severity": "high",
                "method": method,
                "path_template": "/p",
                "url": url,
                "evidence": [
                    {
                        "request_method": method,
                        "request_url": ev_url,
                        "request_headers": headers or {},
                        "response_status": 200,
                        "matcher": "m",
                    }
                ],
            }
        ],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_replay_requires_an_operator_named_target(tmp_path):
    report = _report(tmp_path, url=BASE, ev_url=f"{BASE}/p")
    result = CliRunner().invoke(main, ["replay", report])
    assert result.exit_code != 0
    assert "--target" in result.output


@respx.mock
def test_replay_skips_evidence_aimed_at_another_host_or_port(tmp_path):
    docker = respx.post("http://127.0.0.1:2375/containers/create").mock(
        return_value=httpx.Response(201)
    )
    report = _report(
        tmp_path, url="http://127.0.0.1:2375/", method="POST",
        ev_url="http://127.0.0.1:2375/containers/create",
    )
    result = CliRunner().invoke(
        main, ["replay", report, "--target", BASE, "--allow-post"]
    )
    assert result.exit_code == 0, result.output
    assert "OUT OF SCOPE" in result.output
    assert not docker.called


def test_replay_blocks_post_without_allow_post(tmp_path):
    report = _report(tmp_path, url=BASE, ev_url=f"{BASE}/p", method="POST")
    result = CliRunner().invoke(main, ["replay", report, "--target", BASE])
    assert "BLOCKED (pass --allow-post)" in result.output


@respx.mock
def test_replay_drops_stored_host_header(tmp_path):
    route = respx.get(f"{BASE}/p").mock(return_value=httpx.Response(200, text="x"))
    report = _report(
        tmp_path, url=BASE, ev_url=f"{BASE}/p",
        headers={"Host": "internal-admin.local", "X-Trace": "1"},
    )
    CliRunner().invoke(main, ["replay", report, "--target", BASE])
    assert route.called
    sent = route.calls.last.request
    assert sent.headers["host"] == "127.0.0.1:8000"
    assert sent.headers["x-trace"] == "1"


def test_replay_prints_report_fields_literally(tmp_path):
    report = _report(tmp_path, url=BASE, ev_url=f"{BASE}/p", method="POST")
    doc = json.loads(open(report).read())
    doc["findings"][0]["path_template"] = "/x [/red][green]CONFIRMED[/green] \x1b[2K"
    open(report, "w").write(json.dumps(doc))
    result = CliRunner().invoke(main, ["replay", report, "--target", BASE])
    assert "[green]CONFIRMED[/green]" in result.output
    assert "\x1b" not in result.output
