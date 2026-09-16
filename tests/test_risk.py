"""Accepted-risk register, baseline diff, and `heimdall gate`."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from heimdall.cli import main
from heimdall.models import Evidence, Finding, Severity
from heimdall.report import render
from heimdall.risk import (
    RiskRegisterError,
    apply_filters,
    fail_on,
    load_register,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "benchmarks" / "expected" / "vulnapp.json"
REGISTER = ROOT / "accepted-risk.yml"


def _finding(**kw) -> Finding:
    base = dict(
        check_id="sqli",
        title="t",
        severity=Severity.HIGH,
        cwe="CWE-89",
        owasp_api="API8:2023",
        wstg="WSTG-INPV-05",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        method="GET",
        path_template="/api/products/search",
        url="http://127.0.0.1:8000/api/products/search",
        evidence=[Evidence(request_method="GET", request_url="http://x", matcher="err")],
    )
    base.update(kw)
    return Finding(**base)


def _write_register(path: Path, rows: list[dict]) -> Path:
    path.write_text(yaml.safe_dump({"version": 1, "accepted": rows}), encoding="utf-8")
    return path


def test_load_register_rejects_missing_owner_and_expiry(tmp_path):
    bad = tmp_path / "risk.yml"
    _write_register(bad, [{"fingerprint": "d1461dd77a48"}])
    with pytest.raises(RiskRegisterError, match="missing owner"):
        load_register(bad)

    _write_register(
        bad,
        [{"fingerprint": "d1461dd77a48", "owner": "dee"}],
    )
    with pytest.raises(RiskRegisterError, match="missing expiry"):
        load_register(bad)


def test_load_register_rejects_duplicate_and_bad_fingerprint(tmp_path):
    bad = tmp_path / "risk.yml"
    row = {"fingerprint": "d1461dd77a48", "owner": "dee", "expiry": "2027-03-15"}
    _write_register(bad, [row, dict(row)])
    with pytest.raises(RiskRegisterError, match="duplicate"):
        load_register(bad)

    _write_register(bad, [{"fingerprint": "nope", "owner": "dee", "expiry": "2027-03-15"}])
    with pytest.raises(RiskRegisterError, match="12-char hex"):
        load_register(bad)


def test_partition_suppresses_active_but_not_expired(tmp_path):
    planted = _finding()
    extra = _finding(check_id="exposure", path_template="/api/debug/users")
    reg = tmp_path / "risk.yml"
    _write_register(
        reg,
        [
            {
                "fingerprint": planted.fingerprint,
                "owner": "dee",
                "expiry": "2027-03-15",
                "reason": "demo",
            },
            {
                "fingerprint": extra.fingerprint,
                "owner": "dee",
                "expiry": "2020-01-01",
                "reason": "expired",
            },
        ],
    )
    kept, stats = load_register(reg).partition(
        [planted, extra], today=date(2026, 9, 15)
    )
    assert [f.fingerprint for f in kept] == [extra.fingerprint]
    assert [f.fingerprint for f in stats.suppressed] == [planted.fingerprint]
    assert [f.fingerprint for f in stats.expired_hits] == [extra.fingerprint]


def test_apply_filters_accepted_then_baseline(tmp_path):
    planted = _finding()
    known = _finding(check_id="exposure", path_template="/api/debug/users")
    brand_new = _finding(check_id="ssrf", path_template="/api/url-preview")

    reg = tmp_path / "risk.yml"
    _write_register(
        reg,
        [{"fingerprint": planted.fingerprint, "owner": "dee", "expiry": "2027-03-15"}],
    )
    baseline = tmp_path / "prior.json"
    baseline.write_text(
        render("json", [known], target="http://127.0.0.1:8000"), encoding="utf-8"
    )

    kept, stats = apply_filters(
        [planted, known, brand_new],
        accepted_risk=reg,
        baseline=baseline,
        today=date(2026, 9, 15),
    )
    assert [f.check_id for f in kept] == ["ssrf"]
    assert len(stats.suppressed) == 1
    assert fail_on(kept, "high") is True
    assert fail_on([], "high") is False


def test_repo_register_covers_vulnapp_ground_truth():
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
    register = load_register(REGISTER)
    assert register.entries
    assert all(e.owner and e.reason for e in register.entries)
    today = date(2026, 9, 15)
    active = {
        e.fingerprint for e in register.entries if e.is_active(today)
    }
    missing = []
    for row in expected:
        if not row.get("must_detect", True):
            continue
        fp = Finding.fingerprint_key(row["check"], row["method"], row["path"])
        if fp not in active:
            missing.append(f"{row['id']} ({fp})")
    assert missing == [], (
        "accepted-risk.yml must list an unexpired entry for every "
        f"must_detect vulnapp row: {missing}"
    )


def test_gate_repo_register_clears_vulnapp_ground_truth(tmp_path):
    """The committed register must be enough for `heimdall gate --fail-on high`."""
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))["expected"]
    findings = [
        _finding(
            check_id=row["check"],
            method=row["method"],
            path_template=row["path"],
            severity=Severity.CRITICAL if "alg=none" in row["id"] else Severity.HIGH,
        )
        for row in expected
        if row.get("must_detect", True)
    ]
    report = _write_report(tmp_path / "vulnapp.json", findings)
    failed = CliRunner().invoke(main, ["gate", str(report), "--fail-on", "high"])
    assert failed.exit_code == 2, failed.output
    gated = CliRunner().invoke(
        main,
        [
            "gate",
            str(report),
            "--accepted-risk",
            str(REGISTER),
            "--fail-on",
            "high",
        ],
    )
    assert gated.exit_code == 0, gated.output


def _write_report(path: Path, findings: list[Finding]) -> Path:
    path.write_text(render("json", findings, target="http://127.0.0.1:8000"), encoding="utf-8")
    return path


def test_gate_exits_2_on_high_and_0_after_accepted_risk(tmp_path):
    planted = _finding()
    report = _write_report(tmp_path / "vulnapp.json", [planted])
    runner = CliRunner()

    failed = runner.invoke(main, ["gate", str(report), "--fail-on", "high"])
    assert failed.exit_code == 2, failed.output

    reg = _write_register(
        tmp_path / "risk.yml",
        [{"fingerprint": planted.fingerprint, "owner": "dee", "expiry": "2027-03-15"}],
    )
    gated = runner.invoke(
        main,
        ["gate", str(report), "--accepted-risk", str(reg), "--fail-on", "high"],
    )
    assert gated.exit_code == 0, gated.output
    text = (gated.output or "") + (gated.stderr or "")
    assert "Suppressed 1" in text


def test_gate_baseline_keeps_only_new(tmp_path):
    old = _finding()
    new = _finding(check_id="ssrf", path_template="/api/url-preview", severity=Severity.HIGH)
    report = _write_report(tmp_path / "current.json", [old, new])
    prior = _write_report(tmp_path / "prior.json", [old])
    out = tmp_path / "gated.json"

    result = CliRunner().invoke(
        main,
        [
            "gate",
            str(report),
            "--baseline",
            str(prior),
            "--fail-on",
            "high",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 2, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["total"] == 1
    assert doc["findings"][0]["check_id"] == "ssrf"


def test_gate_rejects_bad_register(tmp_path):
    report = _write_report(tmp_path / "r.json", [_finding()])
    bad = tmp_path / "risk.yml"
    bad.write_text("accepted: not-a-list\n", encoding="utf-8")
    result = CliRunner().invoke(
        main, ["gate", str(report), "--accepted-risk", str(bad)]
    )
    assert result.exit_code != 0
    assert "accepted" in result.output


def test_gate_converts_json_report_to_sarif(tmp_path):
    report = _write_report(tmp_path / "vulnapp.json", [_finding()])
    out = tmp_path / "report.sarif"
    result = CliRunner().invoke(
        main, ["gate", str(report), "--format", "sarif", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "sqli"
