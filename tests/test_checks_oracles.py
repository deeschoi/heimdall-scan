"""Oracle-level unit tests for detection logic (no network).

Each test encodes a technique from the payload sources so a regression in a
check is caught without booting a lab.
"""

from oedipus.checks.sqli import SqliCheck
from oedipus.checks.exposure import ExposureCheck


def test_sqli_oracle_detects_engine_errors():
    c = SqliCheck()
    assert c.oracle(500, "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError)")
    assert c.oracle(500, "You have an error in your SQL syntax near '\\''")
    assert c.oracle(500, "psycopg2.ProgrammingError: syntax error at or near")


def test_sqli_oracle_ignores_clean_responses():
    c = SqliCheck()
    assert not c.oracle(200, '{"user": "admin", "email": "a@b.com"}')
    assert not c.oracle(404, "Not found")


def test_exposure_detects_sensitive_keys_in_json():
    c = ExposureCheck()
    body = '{"users":[{"username":"n1","password":"pass1"}]}'
    assert c._leaked_keys(body) == {"password"}


def test_exposure_ignores_null_or_empty_sensitive_fields():
    c = ExposureCheck()
    assert c._leaked_keys('{"password": null, "token": ""}') == set()


def test_exposure_oracle_requires_success_status():
    c = ExposureCheck()
    body = '{"secret": "abc"}'
    assert c.oracle(200, body)
    assert not c.oracle(403, body)
