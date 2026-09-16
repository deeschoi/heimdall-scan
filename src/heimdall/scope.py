"""Safe-by-default scope enforcement.

A security tool that scans the wrong host gets its author in legal trouble.
Heimdall refuses to touch anything outside an explicit allowlist. Localhost and
RFC1918 hosts are allowed by default (labs run there); anything public requires
``--i-understand`` on the CLI, which adds the host to the allowlist explicitly.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when a request would leave the allowed scope."""


def _is_private_host(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    # Resolve names once; loopback aliases (e.g. *.localhost) are common in labs.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


@dataclass
class Scope:
    allow_hosts: set[str] = field(default_factory=set)
    allow_public: bool = False  # set by --i-understand

    @classmethod
    def from_targets(cls, targets: list[str], allow_public: bool = False) -> "Scope":
        hosts = set()
        for t in targets:
            if not t:
                continue
            host = urlsplit(t if "://" in t else f"http://{t}").hostname
            if host:
                hosts.add(host)
        return cls(allow_hosts=hosts, allow_public=allow_public)

    def add(self, url: str) -> None:
        host = urlsplit(url).hostname
        if host:
            self.allow_hosts.add(host)

    def check(self, url: str) -> None:
        host = urlsplit(url).hostname
        if not host:
            raise ScopeError(f"Cannot determine host for URL: {url!r}")
        if host in self.allow_hosts:
            return
        if _is_private_host(host):
            self.allow_hosts.add(host)
            return
        if self.allow_public:
            self.allow_hosts.add(host)
            return
        raise ScopeError(
            f"Refusing to scan out-of-scope host {host!r}. "
            f"Add it to --scope or pass --i-understand to allow public targets."
        )
