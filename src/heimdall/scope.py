"""Safe-by-default scope enforcement.

A security tool that scans the wrong host gets its author in legal trouble.
Heimdall refuses to touch any host that was not named as a target or via
``--scope``. Named loopback and RFC1918 hosts are allowed. A named public
host requires ``--i-understand``.

Scope is ``host:port``, not just host: a target named as
``http://127.0.0.1:8000`` allows port 8000 on that host and nothing else. An
entry named as a bare host (``--scope 10.0.0.5``, no scheme, no port) allows
every port on it.

A hostname counts as private only when *every* address it resolves to is
private. The addresses vetted by :meth:`Scope.validate` are pinned, and
:class:`~heimdall.http_client.HttpClient` connects only to them, so a DNS
answer that changes after validation (rebinding) cannot steer traffic to a
public address.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LOCAL_NAMES = {"localhost"}


class ScopeError(Exception):
    """Raised when a request would leave the allowed scope."""


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _resolve(host: str) -> list[str]:
    """Every address ``host`` resolves to, in resolver order, de-duplicated."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def _is_private_host(host: str) -> bool:
    if _is_ip_literal(host):
        return _is_private_ip(host)
    addrs = _resolve(host)
    if not addrs:
        # A loopback alias that does not resolve here is still local by name.
        return host in _LOCAL_NAMES or host.endswith(".localhost")
    # Every address must be private: httpx connects to whichever one answers,
    # so a single public record would let traffic leave the lab.
    return all(_is_private_ip(a) for a in addrs)


def _split(entry: str) -> tuple[Optional[str], Optional[int], bool]:
    """Return ``(host, port, any_port)`` for a target or ``--scope`` entry."""
    has_scheme = "://" in entry
    parts = urlsplit(entry if has_scheme else f"http://{entry}")
    host = parts.hostname
    try:
        port = parts.port
    except ValueError:
        return None, None, False
    if port is None and has_scheme:
        port = _DEFAULT_PORTS.get(parts.scheme.lower())
    any_port = port is None
    return host, port, any_port


def url_host_port(url: str) -> tuple[Optional[str], Optional[int]]:
    """Host and effective port of an http(s) URL (``None`` when not http(s))."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None, None
    try:
        port = parts.port
    except ValueError:
        return parts.hostname, None
    return parts.hostname, port if port is not None else _DEFAULT_PORTS[scheme]


@dataclass
class Scope:
    allow_hosts: set[str] = field(default_factory=set)
    allow_public: bool = False  # set by --i-understand
    # host -> allowed ports; ``None`` means every port on that host.
    allow_ports: dict[str, Optional[set[int]]] = field(default_factory=dict)
    # host -> addresses vetted by validate(); HttpClient connects only to these.
    pinned: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_targets(cls, targets: list[str], allow_public: bool = False) -> "Scope":
        scope = cls(allow_public=allow_public)
        for t in targets:
            if t:
                scope.add(t)
        return scope

    def add(self, entry: str) -> None:
        host, port, any_port = _split(entry)
        if not host:
            return
        self.allow_hosts.add(host)
        if any_port:
            self.allow_ports[host] = None
            return
        if host in self.allow_ports and self.allow_ports[host] is None:
            return
        self.allow_ports.setdefault(host, set()).add(port)  # type: ignore[union-attr]

    def validate(self) -> None:
        """Refuse named public hosts unless ``--i-understand`` was set.

        On success, pin each named hostname to the addresses that were vetted.
        """
        if self.allow_public:
            return
        public = sorted(h for h in self.allow_hosts if not _is_private_host(h))
        if public:
            listed = ", ".join(repr(h) for h in public)
            raise ScopeError(
                f"Refusing to scan public host(s) {listed}. "
                f"Pass --i-understand to allow public targets."
            )
        for host in self.allow_hosts:
            if _is_ip_literal(host):
                continue
            addrs = _resolve(host)
            if addrs:
                self.pinned[host] = addrs

    def check(self, url: str) -> None:
        host, port = url_host_port(url)
        if not host:
            raise ScopeError(f"Cannot determine an http(s) host for URL: {url!r}")
        if host not in self.allow_hosts:
            raise ScopeError(
                f"Refusing to scan out-of-scope host {host!r}. "
                f"Add it with --scope. Public hosts also need --i-understand."
            )
        ports = self.allow_ports.get(host)
        if ports is None:
            return
        if port not in ports:
            allowed = ", ".join(str(p) for p in sorted(ports))
            raise ScopeError(
                f"Refusing to scan {host}:{port}: only port(s) {allowed} are in scope "
                f"for that host. Add it with --scope {host}:{port}."
            )
