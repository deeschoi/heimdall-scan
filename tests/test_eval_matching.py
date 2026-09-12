from oedipus.eval.harness import _finding_key, _key
from oedipus.models import Finding, Severity


def test_key_matches_finding_key():
    f = Finding(
        check_id="bola", title="", severity=Severity.HIGH, cwe="CWE-639",
        owasp_api="API1:2023", wstg="WSTG-ATHZ-04", cvss_vector="x",
        method="get", path_template="/books/v1/{book_title}", url="http://x",
    )
    expected_key = _key("bola", "GET", "/books/v1/{book_title}")
    assert _finding_key(f) == expected_key


def test_key_is_case_insensitive_on_method():
    assert _key("sqli", "get", "/a") == _key("sqli", "GET", "/a")
