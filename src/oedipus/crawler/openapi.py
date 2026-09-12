"""OpenAPI-first endpoint discovery.

Oedipus crawls the API *contract*, not scraped HTML: given an OpenAPI 3
document it yields one :class:`Endpoint` per operation, with typed parameters.
This is why the scanner works against JSON APIs that have no browsable UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import httpx


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


def load_spec(source: str, client: Optional[httpx.Client] = None) -> dict[str, Any]:
    """Load an OpenAPI document from a URL or local path."""
    import json

    import yaml

    if source.startswith(("http://", "https://")):
        owns = client is None
        client = client or httpx.Client(timeout=10.0, verify=False)
        try:
            text = client.get(source).text
        finally:
            if owns:
                client.close()
    else:
        with open(source, "r", encoding="utf-8") as fh:
            text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def parse_endpoints(spec: dict[str, Any]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    methods = {"get", "post", "put", "delete", "patch", "head", "options"}
    for path, item in (spec.get("paths") or {}).items():
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


def iter_specs(sources: Iterable[str]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for src in sources:
        endpoints.extend(parse_endpoints(load_spec(src)))
    return endpoints
