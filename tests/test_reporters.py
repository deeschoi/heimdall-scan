import json

from oedipus.models import Evidence, Finding, Severity
from oedipus.report import render


def _findings():
    return [
        Finding(
            check_id="sqli",
            title="Error-based SQL injection",
            severity=Severity.HIGH,
            cwe="CWE-89",
            owasp_api="API8:2023",
            wstg="WSTG-INPV-05",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            method="GET",
            path_template="/users/v1/{username}",
            url="http://127.0.0.1:5001/users/v1/admin'",
            evidence=[Evidence(request_method="GET", request_url="http://x", matcher="err")],
        )
    ]


def test_sarif_shape_is_valid():
    doc = json.loads(render("sarif", _findings(), target="http://127.0.0.1:5001"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "sqli"
    assert rule["properties"]["cwe"] == "CWE-89"
    result = run["results"][0]
    assert result["ruleId"] == "sqli"
    assert result["level"] == "error"
    assert "partialFingerprints" in result


def test_json_report_summary():
    doc = json.loads(render("json", _findings()))
    assert doc["summary"]["high"] == 1
    assert doc["summary"]["total"] == 1


def test_markdown_has_evidence_section():
    md = render("md", _findings(), target="t")
    assert "# Oedipus scan report" in md
    assert "Evidence #1" in md
    assert "CWE-89" in md
