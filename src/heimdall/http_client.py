"""Thin httpx wrapper that enforces scope, rate-limits, and captures evidence.

Every request goes through :class:`HttpClient` so that:
- scope is checked before a packet leaves the box (redirects included),
- connections to named hostnames go only to the addresses scope vetted,
- methods other than GET/HEAD/OPTIONS/POST are blocked unless ``unsafe`` is set,
- an :class:`~heimdall.models.Evidence` object can be built from any exchange,
  with every credential the scan used removed from it.
"""

from __future__ import annotations

import re
import time
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from heimdall.models import Evidence
from heimdall.scope import Scope, url_host_port

# Methods a scan may send without --unsafe. Anything else (PUT, PATCH, DELETE,
# and non-standard verbs such as MOVE or PURGE) can change or destroy state.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
_MAX_BODY_EXCERPT = 2048
_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
# Header names that look like they carry a credential, whatever the target calls it.
_SENSITIVE_NAME = re.compile(
    r"auth|token|secret|session|passw|api[-_]?key|cookie|credential|csrf|xsrf|signature",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"
# Shorter values are too likely to collide with ordinary text to mask safely.
_MIN_SECRET_LEN = 6


def split_userinfo(url: str) -> tuple[str, Optional[tuple[str, str]]]:
    """Return ``url`` without ``user:pass@`` and the credentials it carried."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url, None
    userinfo, _, hostport = parts.netloc.rpartition("@")
    user, _, password = userinfo.partition(":")
    clean = urlunsplit((parts.scheme, hostport, parts.path, parts.query, parts.fragment))
    return clean, (user, password)


def strip_userinfo(url: str) -> str:
    return split_userinfo(url)[0]


class _PinnedTransport(httpx.BaseTransport):
    """Scope-check every request and connect only to vetted addresses.

    httpx resolves hostnames again at connect time, so a DNS answer that
    changed after :meth:`Scope.validate` could otherwise reach a public
    address. For a pinned host the request goes to each vetted address in
    turn, with the original ``Host`` header and TLS server name kept.
    """

    def __init__(self, scope: Scope, inner: httpx.BaseTransport) -> None:
        self._scope = scope
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Also covers redirect hops, which never pass through HttpClient.request.
        self._scope.check(str(request.url))
        host = request.url.host
        addrs = self._scope.pinned.get(host)
        if not addrs:
            return self._inner.handle_request(request)
        last: Optional[Exception] = None
        for addr in addrs:
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=addr),
                headers=request.headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": host},
            )
            try:
                return self._inner.handle_request(pinned)
            except httpx.ConnectError as exc:
                last = exc
        assert last is not None
        raise last

    def close(self) -> None:
        self._inner.close()


class HttpClient:
    def __init__(
        self,
        scope: Scope,
        rate_limit_per_sec: float = 20.0,
        timeout: float = 10.0,
        unsafe: bool = False,
        verify_tls: bool = True,
        follow_redirects: bool = False,
    ) -> None:
        self.scope = scope
        self.unsafe = unsafe
        self.verify_tls = verify_tls
        self._min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec else 0.0
        self._last = 0.0
        self._secret_names: set[str] = set()
        self._secret_values: set[str] = set()
        self._host_auth: dict[tuple[Optional[str], Optional[int]], httpx.BasicAuth] = {}
        transport = _PinnedTransport(scope, httpx.HTTPTransport(verify=verify_tls))
        self._client = httpx.Client(
            timeout=timeout, follow_redirects=follow_redirects, transport=transport
        )

    # --- credentials --------------------------------------------------
    def register_secret(
        self, header: Optional[str] = None, value: Optional[str] = None
    ) -> None:
        """Mark a header name and/or value as a credential to keep out of evidence."""
        if header:
            self._secret_names.add(header.lower())
        if value and len(value) >= _MIN_SECRET_LEN:
            self._secret_values.add(value)

    def adopt_userinfo(self, url: str) -> str:
        """Strip ``user:pass@`` from ``url``; send it as Basic auth to that host only."""
        clean, creds = split_userinfo(url)
        if creds:
            self._host_auth[url_host_port(clean)] = httpx.BasicAuth(*creds)
            self.register_secret(value=creds[1])
        return clean

    # --- requests -----------------------------------------------------
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
    ) -> httpx.Response:
        method = method.upper()
        url = self.adopt_userinfo(url)
        self.scope.check(url)
        if method not in SAFE_METHODS and not self.unsafe:
            raise PermissionError(
                f"Blocked {method} on {url}: only {', '.join(sorted(SAFE_METHODS))} "
                f"are sent without --unsafe."
            )
        self._throttle()
        kwargs = {}
        auth = self._host_auth.get(url_host_port(url))
        if auth is not None:
            kwargs["auth"] = auth
        return self._client.request(
            method, url, headers=headers, json=json, content=content, params=params,
            **kwargs,
        )

    # --- evidence -----------------------------------------------------
    def _is_secret_header(self, name: str) -> bool:
        low = name.lower()
        return (
            low in _SENSITIVE_HEADERS
            or low in self._secret_names
            or bool(_SENSITIVE_NAME.search(low))
        )

    def _mask(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return text
        for value in sorted(self._secret_values, key=len, reverse=True):
            if value in text:
                text = text.replace(value, _REDACTED)
        return text

    def _request_headers(self, headers) -> dict[str, str]:
        return {
            k: self._mask(v) or ""
            for k, v in headers.items()
            if not self._is_secret_header(k)
        }

    def _response_headers(self, headers) -> dict[str, str]:
        return {
            k: (_REDACTED if self._is_secret_header(k) else (self._mask(v) or ""))
            for k, v in headers.items()
        }

    def evidence_from(
        self, response: httpx.Response, matcher: str = "", note: str = ""
    ) -> Evidence:
        req = response.request
        body = None
        if req.content:
            try:
                body = self._mask(req.content.decode("utf-8", "replace"))
            except Exception:
                body = None
        return Evidence(
            request_method=req.method,
            request_url=self._mask(strip_userinfo(str(req.url))) or "",
            request_headers=self._request_headers(req.headers),
            request_body=body[:_MAX_BODY_EXCERPT] if body else body,
            response_status=response.status_code,
            response_headers=self._response_headers(response.headers),
            response_body_excerpt=(self._mask(response.text) or "")[:_MAX_BODY_EXCERPT],
            matcher=matcher,
            note=note,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
