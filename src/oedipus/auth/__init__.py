"""Authentication adapters.

IDOR/BOLA detection is meaningless without at least two authenticated
identities, so auth is a first-class concept. An :class:`Identity` carries the
headers Oedipus attaches to a request when acting *as* that principal.

Adapters are described declaratively in a suite YAML (``auth:`` block) and
built by :func:`build_identities`, so no target-specific code lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


@dataclass
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    token: Optional[str] = None

    def apply(self, headers: Optional[dict[str, str]] = None) -> dict[str, str]:
        merged = dict(headers or {})
        merged.update(self.headers)
        return merged


def _register_and_login(
    base_url: str,
    spec: dict[str, Any],
    client: httpx.Client,
) -> Identity:
    """Run an optional register step then a login step, extract a token.

    ``spec`` shape (from suite YAML)::

        register: { path: /users/v1/register, json: {...} }   # optional
        login:    { path: /users/v1/login, json: {...},
                    token_field: auth_token, header: Authorization,
                    prefix: "Bearer " }
    """
    reg = spec.get("register")
    if reg:
        client.post(base_url.rstrip("/") + reg["path"], json=reg.get("json", {}))

    login = spec["login"]
    resp = client.post(base_url.rstrip("/") + login["path"], json=login.get("json", {}))
    token_field = login.get("token_field", "auth_token")
    token = None
    try:
        token = _dig(resp.json(), token_field)
    except Exception:
        token = None

    header_name = login.get("header", "Authorization")
    prefix = login.get("prefix", "Bearer ")
    headers = {header_name: f"{prefix}{token}"} if token else {}
    return Identity(name=spec.get("name", "user"), headers=headers, token=token)


def _dig(data: Any, dotted: str) -> Any:
    cur = data
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def build_identities(
    base_url: str,
    auth_cfg: dict[str, Any],
    spec: Optional[dict[str, Any]] = None,
    verify_tls: bool = False,
) -> dict[str, Identity]:
    """Build named identities from a suite ``auth:`` block.

    Supported per-identity ``type`` values:
      * ``login``  – register (optional) + login, extract bearer token
      * ``bearer`` – a static token supplied in the suite/env
      * ``header`` – static headers (e.g. a raw cookie)
      * ``none``   – the anonymous identity
    """
    identities: dict[str, Identity] = {"anon": Identity(name="anon")}
    if not auth_cfg:
        return identities

    with httpx.Client(timeout=10.0, verify=verify_tls) as client:
        for name, cfg in auth_cfg.items():
            kind = cfg.get("type", "login")
            if kind == "login":
                ident = _register_and_login(base_url, cfg, client)
            elif kind == "bearer":
                header = cfg.get("header", "Authorization")
                prefix = cfg.get("prefix", "Bearer ")
                ident = Identity(
                    name=name,
                    headers={header: f"{prefix}{cfg['token']}"},
                    token=cfg["token"],
                )
            elif kind == "header":
                ident = Identity(name=name, headers=dict(cfg.get("headers", {})))
            else:  # none
                ident = Identity(name=name)
            ident.name = name
            identities[name] = ident
    return identities
