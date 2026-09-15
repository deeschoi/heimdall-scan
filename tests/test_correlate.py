from oedipus.correlate import correlate, render
from oedipus.models import Finding, Severity


def _f(check_id, method, path, cwe, url="http://x"):
    return Finding(
        check_id=check_id, title=check_id, severity=Severity.HIGH, cwe=cwe,
        owasp_api="API8:2023", wstg="WSTG-INPV-05", cvss_vector="x",
        method=method, path_template=path, url=url,
    )


def test_matching_method_path_cwe_correlates():
    dast = [_f("sqli", "GET", "/api/products/search", "CWE-89")]
    sast = [_f("sast.sql-string-concat", "GET", "/api/products/search", "CWE-89")]
    result = correlate(dast, sast)
    assert len(result.correlated) == 1
    assert not result.dast_only
    assert not result.sast_only


def test_method_is_matched_case_insensitively():
    dast = [_f("sqli", "get", "/api/x", "CWE-89")]
    sast = [_f("sast.x", "GET", "/api/x", "CWE-89")]
    result = correlate(dast, sast)
    assert len(result.correlated) == 1


def test_mismatched_cwe_does_not_correlate():
    dast = [_f("sqli", "GET", "/api/x", "CWE-89")]
    sast = [_f("sast.x", "GET", "/api/x", "CWE-918")]
    result = correlate(dast, sast)
    assert not result.correlated
    assert len(result.dast_only) == 1
    assert len(result.sast_only) == 1


def test_unmatched_dast_and_sast_go_to_their_own_only_lists():
    dast = [_f("bola", "GET", "/api/notes/{id}", "CWE-639")]
    sast = [_f("sast.ssrf", "POST", "/api/url-preview-safe", "CWE-918")]
    result = correlate(dast, sast)
    assert not result.correlated
    assert result.dast_only == dast
    assert result.sast_only == sast


def test_each_sast_finding_consumed_at_most_once():
    dast = [
        _f("sqli", "GET", "/api/x", "CWE-89"),
        _f("sqli2", "GET", "/api/x", "CWE-89"),
    ]
    sast = [_f("sast.x", "GET", "/api/x", "CWE-89")]
    result = correlate(dast, sast)
    assert len(result.correlated) == 1
    assert len(result.dast_only) == 1
    assert not result.sast_only


def test_render_json_round_trips_summary_counts():
    import json

    dast = [_f("sqli", "GET", "/api/x", "CWE-89")]
    sast = [_f("sast.x", "GET", "/api/x", "CWE-89")]
    result = correlate(dast, sast)
    doc = json.loads(render(result, "json"))
    assert doc["summary"] == {"correlated": 1, "dast_only": 0, "sast_only": 0}


def test_render_markdown_lists_each_section():
    dast = [_f("sqli", "GET", "/api/x", "CWE-89"), _f("bola", "GET", "/api/y", "CWE-639")]
    sast = [_f("sast.x", "GET", "/api/x", "CWE-89"), _f("sast.z", "POST", "/api/z", "CWE-918")]
    result = correlate(dast, sast)
    md = render(result, "md")
    assert "Correlated" in md
    assert "DAST only" in md
    assert "SAST only" in md
    assert "bola" in md
    assert "sast.z" in md
