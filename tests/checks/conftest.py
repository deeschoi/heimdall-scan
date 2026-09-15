"""Fixtures for check-level unit tests.

Each check runs against a real :class:`HttpClient` / :class:`ScanContext` with
``respx`` standing in for the target, so the tests exercise the same code path a
live scan does — scope check, rate limiter, evidence capture — without a lab.
"""

from __future__ import annotations

import pytest

from oedipus.checks import ScanContext
from oedipus.http_client import HttpClient
from oedipus.scope import Scope

BASE = "http://127.0.0.1:8000"


@pytest.fixture
def make_ctx():
    """Build ScanContexts pointed at ``BASE`` with throttling disabled."""
    clients: list[HttpClient] = []

    def _make(**kwargs) -> ScanContext:
        client = HttpClient(Scope.from_targets([BASE]), rate_limit_per_sec=0)
        clients.append(client)
        return ScanContext(base_url=BASE, client=client, **kwargs)

    yield _make
    for c in clients:
        c.close()


@pytest.fixture
def payloads_dir(tmp_path):
    """Write a payload file and return its directory (as ctx.payloads_dir)."""

    def _write(name: str, lines: list[str]):
        (tmp_path / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return tmp_path

    return _write
