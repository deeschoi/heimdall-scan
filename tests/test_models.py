from heimdall.models import Evidence, Finding, Severity


def _finding(**kw):
    base = dict(
        check_id="bola",
        title="t",
        severity=Severity.HIGH,
        cwe="CWE-639",
        owasp_api="API1:2023",
        wstg="WSTG-ATHZ-04",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        method="GET",
        path_template="/books/v1/{book_title}",
        url="http://127.0.0.1:5001/books/v1/x",
    )
    base.update(kw)
    return Finding(**base)


def test_fingerprint_stable_and_keyed_on_endpoint():
    a = _finding()
    b = _finding(url="http://127.0.0.1:5001/books/v1/other")
    # Same check+method+path_template -> same fingerprint regardless of concrete url.
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint == Finding.fingerprint_key("bola", "GET", "/books/v1/{book_title}")
    c = _finding(method="POST")
    assert a.fingerprint != c.fingerprint


def test_severity_ordering_and_sarif_level():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.LOW.sarif_level == "note"


def test_to_dict_roundtrip_fields():
    f = _finding(evidence=[Evidence(request_method="GET", request_url="u")])
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["fingerprint"] == f.fingerprint
    assert d["evidence"][0]["request_method"] == "GET"
