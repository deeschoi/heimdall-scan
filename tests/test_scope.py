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
