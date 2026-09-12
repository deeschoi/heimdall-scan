from oedipus.scope import Scope, ScopeError

import pytest


def test_localhost_allowed_by_default():
    s = Scope.from_targets([])
    s.check("http://127.0.0.1:5001/x")  # no raise
    s.check("http://localhost:8888/y")


def test_public_host_blocked_without_flag():
    s = Scope.from_targets(["http://127.0.0.1:5001"])
    with pytest.raises(ScopeError):
        s.check("https://example.com/")


def test_public_host_allowed_with_flag():
    s = Scope.from_targets([], allow_public=True)
    s.check("https://example.com/")  # no raise


def test_explicit_scope_host_allowed():
    s = Scope.from_targets(["http://testphp.vulnweb.com"])
    s.check("http://testphp.vulnweb.com/artists.php")
