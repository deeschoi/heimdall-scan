from oedipus import sast
from oedipus.models import Severity
from oedipus.sast.routes import Route, RouteIndex


def _index():
    return RouteIndex(
        routes=[Route(method="POST", path="/api/register", file="app.py", start_line=1, end_line=1)],
        models=[],
    )


def _result(rule_id="jwt-hardcoded-secret", cwe="CWE-347", severity="ERROR", line=46, oedipus_severity=None):
    metadata = {"cwe": cwe, "owasp": "API2:2023"}
    if oedipus_severity:
        metadata["oedipus_severity"] = oedipus_severity
    return {
        "check_id": f"semgrep-rules.{rule_id}",
        "path": "app.py",
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": "a JWT secret is hardcoded",
            "severity": severity,
            "metadata": metadata,
            "lines": 'WEAK_JWT_SECRET = "changeme"',
        },
    }


def test_check_id_is_namespaced_and_short_rule_id():
    f = sast._finding_from_result(_result(), _index())
    assert f.check_id == "sast.jwt-hardcoded-secret"


def test_cwe_standards_are_backfilled_from_table():
    f = sast._finding_from_result(_result(cwe="CWE-89"), _index())
    assert f.wstg == "WSTG-INPV-05"
    assert f.cvss_vector.startswith("CVSS:3.1")


def test_severity_prefers_rule_metadata_override():
    f = sast._finding_from_result(_result(severity="ERROR", oedipus_severity="medium"), _index())
    assert f.severity == Severity.MEDIUM


def test_severity_falls_back_to_semgrep_severity():
    f = sast._finding_from_result(_result(severity="WARNING"), _index())
    assert f.severity == Severity.MEDIUM


def test_unresolvable_route_yields_unknown_method_and_empty_path():
    f = sast._finding_from_result(_result(line=999), _index())
    assert f.method == "UNKNOWN"
    assert f.path_template == ""


def test_resolvable_route_fills_method_and_path():
    result = _result(rule_id="mass-assignment-privileged-field", cwe="CWE-915", line=1)
    f = sast._finding_from_result(result, _index())
    assert (f.method, f.path_template) == ("POST", "/api/register")


def test_scan_source_wires_runner_and_route_index(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text('@app.post("/api/x")\ndef h():\n    pass\n')
    monkeypatch.setattr(sast, "run_semgrep", lambda rules_dir, src_dir: [_result(line=2)])
    findings = sast.scan_source("unused-rules-dir", str(tmp_path))
    assert len(findings) == 1
    assert findings[0].check_id == "sast.jwt-hardcoded-secret"
