from heimdall.scope import Scope, ScopeError

import pytest


def test_named_loopback_is_allowed():
    s = Scope.from_targets(["http://127.0.0.1:5001"])
    s.validate()
    s.check("http://127.0.0.1:5001/x")


def test_unlisted_private_host_is_refused():
    s = Scope.from_targets(["http://127.0.0.1:5001"])
    with pytest.raises(ScopeError):
        s.check("http://10.0.0.5/secret")
    with pytest.raises(ScopeError):
        s.check("http://localhost:8888/y")


def test_public_host_blocked_without_flag():
    s = Scope.from_targets(["http://127.0.0.1:5001"])
    with pytest.raises(ScopeError):
        s.check("https://example.com/")


def test_public_target_fails_validate_without_flag():
    s = Scope.from_targets(["http://8.8.8.8"])
    with pytest.raises(ScopeError):
        s.validate()


def test_public_scope_host_fails_validate_without_flag():
    s = Scope.from_targets(["http://127.0.0.1:5001", "https://8.8.8.8"])
    with pytest.raises(ScopeError):
        s.validate()


def test_public_target_allowed_with_flag():
    s = Scope.from_targets(["http://8.8.8.8"], allow_public=True)
    s.validate()
    s.check("http://8.8.8.8/x")


def test_explicit_scope_host_allowed():
    s = Scope.from_targets(["http://testphp.vulnweb.com"], allow_public=True)
    s.validate()
    s.check("http://testphp.vulnweb.com/artists.php")


# --- host:port scope (F18) --------------------------------------------------

def test_target_port_is_the_only_port_in_scope():
    s = Scope.from_targets(["http://127.0.0.1:8000"])
    s.check("http://127.0.0.1:8000/x")
    with pytest.raises(ScopeError):
        s.check("http://127.0.0.1:2375/containers/json")


def test_scheme_default_port_applies_when_target_names_none():
    s = Scope.from_targets(["https://127.0.0.1"])
    s.check("https://127.0.0.1:443/x")
    with pytest.raises(ScopeError):
        s.check("http://127.0.0.1:8080/x")


def test_bare_scope_host_allows_every_port():
    s = Scope.from_targets(["http://127.0.0.1:8000", "10.0.0.5"])
    s.check("http://10.0.0.5:9999/x")


def test_scope_host_with_port_adds_only_that_port():
    s = Scope.from_targets(["http://127.0.0.1:8000", "127.0.0.1:9000"])
    s.check("http://127.0.0.1:9000/x")
    with pytest.raises(ScopeError):
        s.check("http://127.0.0.1:9001/x")


def test_non_http_scheme_is_refused():
    s = Scope.from_targets(["http://127.0.0.1:8000"])
    with pytest.raises(ScopeError):
        s.check("file:///etc/passwd")


# --- private means every address private (F17) -----------------------------

def _fake_resolver(monkeypatch, answers):
    import socket

    def fake(host, *args, **kwargs):
        if host not in answers:
            raise OSError("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in answers[host]]

    monkeypatch.setattr("heimdall.scope.socket.getaddrinfo", fake)


def test_name_with_one_public_record_is_public(monkeypatch):
    _fake_resolver(monkeypatch, {"lab.example": ["127.0.0.1", "8.8.8.8"]})
    s = Scope.from_targets(["http://lab.example:8000"])
    with pytest.raises(ScopeError):
        s.validate()


def test_name_with_only_private_records_is_pinned(monkeypatch):
    _fake_resolver(monkeypatch, {"lab.example": ["10.0.0.7", "127.0.0.1"]})
    s = Scope.from_targets(["http://lab.example:8000"])
    s.validate()
    assert s.pinned["lab.example"] == ["10.0.0.7", "127.0.0.1"]


def test_unresolvable_name_is_not_private(monkeypatch):
    _fake_resolver(monkeypatch, {})
    s = Scope.from_targets(["http://nowhere.example"])
    with pytest.raises(ScopeError):
        s.validate()


def test_allow_public_skips_pinning(monkeypatch):
    _fake_resolver(monkeypatch, {"api.example": ["8.8.8.8"]})
    s = Scope.from_targets(["https://api.example"], allow_public=True)
    s.validate()
    assert s.pinned == {}
