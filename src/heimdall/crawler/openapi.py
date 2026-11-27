"""OpenAPI-first endpoint discovery.

Heimdall crawls the API *contract*, not scraped HTML: given an OpenAPI 3
document it yields one :class:`Endpoint` per operation, with typed parameters.
This is why the scanner works against JSON APIs that have no browsable UI.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover
    from heimdall.http_client import HttpClient


@dataclass
class Param:
    name: str
    location: str  # path | query | header | cookie
    required: bool = False
    schema_type: str = "string"


@dataclass
class Endpoint:
    method: str
    path_template: str  # e.g. /users/v1/{username}
    params: list[Param] = field(default_factory=list)
    summary: str = ""
    request_body_schema: Optional[dict[str, Any]] = None

    @property
    def path_params(self) -> list[Param]:
        return [p for p in self.params if p.location == "path"]

    @property
    def query_params(self) -> list[Param]:
        return [p for p in self.params if p.location == "query"]


def load_spec(source: str, client: Optional["HttpClient"] = None) -> dict[str, Any]:
    """Load an OpenAPI document from a URL or local path.

    A URL is fetched only through ``client`` -- the scan's :class:`HttpClient` --
    so the fetch is scope-checked, rate-limited and honours ``--insecure`` like
    every other request.
    """
    import json

    import yaml

    if source.startswith(("http://", "https://")):
        if client is None:
            raise ValueError(
                f"fetching the OpenAPI spec from {source} needs the scan's HttpClient"
            )
        text = client.request("GET", source).text
    else:
        with open(source, "r", encoding="utf-8") as fh:
            text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def _safe_path(path: Any) -> bool:
    """A spec path must be a rooted path with no control characters.

    Paths are appended to the target's base URL, so a key such as
    ``@127.0.0.1:2375/x`` would otherwise move the request to another
    authority (host and port).
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    return not any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in path)


def parse_endpoints(spec: dict[str, Any]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    methods = {"get", "post", "put", "delete", "patch", "head", "options"}
    for path, item in (spec.get("paths") or {}).items():
        if not _safe_path(path):
            print(
                f"[warn] skipping OpenAPI path {path!r}: not a rooted path",
                file=sys.stderr,
            )
            continue
        shared = item.get("parameters", []) if isinstance(item, dict) else []
        for method, op in (item or {}).items():
            if method not in methods or not isinstance(op, dict):
                continue
            params = [_param(p) for p in shared] + [
                _param(p) for p in op.get("parameters", [])
            ]
            body_schema = None
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                content = rb.get("content", {})
                jsonc = content.get("application/json", {})
                body_schema = jsonc.get("schema")
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path_template=path,
                    params=[p for p in params if p],
                    summary=op.get("summary", ""),
                    request_body_schema=body_schema,
                )
            )
    return endpoints


def _param(raw: dict[str, Any]) -> Optional[Param]:
    if not isinstance(raw, dict) or "name" not in raw:
        return None
    schema = raw.get("schema") or {}
    return Param(
        name=raw["name"],
        location=raw.get("in", "query"),
        required=bool(raw.get("required", False)),
        schema_type=schema.get("type", "string"),
    )


def fill_path(path_template: str, values: dict[str, str]) -> str:
    out = path_template
    for name, val in values.items():
        out = out.replace("{" + name + "}", str(val))
    return out

