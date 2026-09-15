"""Thin httpx wrapper that enforces scope, rate-limits, and captures evidence.

Every request goes through :class:`HttpClient` so that:
- scope is checked before a packet leaves the box,
- destructive methods are blocked unless ``unsafe`` is set,
- an :class:`~oedipus.models.Evidence` object can be built from any exchange.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx

from oedipus.models import Evidence
from oedipus.scope import Scope

_DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}
_MAX_BODY_EXCERPT = 2048


class HttpClient:
    def __init__(
        self,
        scope: Scope,
        rate_limit_per_sec: float = 20.0,
        timeout: float = 10.0,
        unsafe: bool = False,
        verify_tls: bool = False,
        follow_redirects: bool = False,
    ) -> None:
        self.scope = scope
        self.unsafe = unsafe
        self._min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec else 0.0
        self._last = 0.0
        self._client = httpx.Client(
            timeout=timeout, verify=verify_tls, follow_redirects=follow_redirects
        )

    def _throttle(self) -> None:
        if self._min_interval:
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        json: object = None,
        content: Optional[str] = None,
        params: Optional[dict[str, str]] = None,
        allow_destructive: bool = False,
    ) -> httpx.Response:
        method = method.upper()
        self.scope.check(url)
        if method in _DESTRUCTIVE and not (self.unsafe or allow_destructive):
            raise PermissionError(
                f"Blocked destructive {method} on {url}. Pass --unsafe to allow."
            )
        self._throttle()
        return self._client.request(
            method, url, headers=headers, json=json, content=content, params=params
        )

    @staticmethod
    def evidence_from(
        response: httpx.Response, matcher: str = "", note: str = ""
    ) -> Evidence:
        req = response.request
        body = None
        if req.content:
            try:
                body = req.content.decode("utf-8", "replace")[:_MAX_BODY_EXCERPT]
            except Exception:
                body = None
        return Evidence(
            request_method=req.method,
            request_url=str(req.url),
            request_headers={k: v for k, v in req.headers.items() if k.lower() != "authorization"},
            request_body=body,
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body_excerpt=response.text[:_MAX_BODY_EXCERPT],
            matcher=matcher,
            note=note,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
