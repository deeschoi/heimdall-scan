"""Map Python source lines back to the API route they implement.

Semgrep reports a bare file:line. To join a SAST hit with a DAST ``Finding``
on ``(method, path_template, cwe)`` (see :mod:`heimdall.correlate`) we need to
know which route a given line belongs to. This is a lightweight, framework-
agnostic pass over the AST — it looks for any ``@x.get("/path")``-shaped
decorator (works for FastAPI, Flask-RESTful-ish routers, etc. as long as the
decorator is a call whose first argument is a string literal path) rather
than importing FastAPI itself.

A hit that lands inside a Pydantic ``BaseModel`` class (e.g. a mass-
assignment field) is resolved one level indirectly: find route handlers whose
parameter is annotated with that model name.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


@dataclass
class Route:
    method: str
    path: str
    file: str
    start_line: int
    end_line: int
    param_types: set[str] = field(default_factory=set)


@dataclass
class ModelClass:
    name: str
    file: str
    start_line: int
    end_line: int


@dataclass
class RouteIndex:
    routes: list[Route]
    models: list[ModelClass]

    def resolve(self, file: str, line: int) -> Optional[tuple[str, str]]:
        """Return (method, path_template) for a source location, or None."""
        for r in self.routes:
            if r.file == file and r.start_line <= line <= r.end_line:
                return (r.method, r.path)
        for m in self.models:
            if m.file == file and m.start_line <= line <= m.end_line:
                for r in self.routes:
                    if m.name in r.param_types:
                        return (r.method, r.path)
        return None


def build_index(src_dir: str) -> RouteIndex:
    routes: list[Route] = []
    models: list[ModelClass] = []
    for path in sorted(Path(src_dir).rglob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route = _route_from_function(node, rel)
                if route:
                    routes.append(route)
            elif isinstance(node, ast.ClassDef) and _is_pydantic_model(node):
                models.append(
                    ModelClass(
                        name=node.name,
                        file=rel,
                        start_line=node.lineno,
                        end_line=_end_line(node),
                    )
                )
    return RouteIndex(routes=routes, models=models)


def _route_from_function(node, rel: str) -> Optional[Route]:
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        if dec.func.attr not in _HTTP_METHODS:
            continue
        if not dec.args or not isinstance(dec.args[0], ast.Constant) or not isinstance(dec.args[0].value, str):
            continue
        return Route(
            method=dec.func.attr.upper(),
            path=dec.args[0].value,
            file=rel,
            start_line=node.lineno,
            end_line=_end_line(node),
            param_types=_param_type_names(node),
        )
    return None


def _param_type_names(node) -> set[str]:
    names: set[str] = set()
    for arg in list(node.args.args) + list(node.args.kwonlyargs):
        if arg.annotation is not None:
            names |= {n.id for n in ast.walk(arg.annotation) if isinstance(n, ast.Name)}
    return names


def _is_pydantic_model(node: ast.ClassDef) -> bool:
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id == "BaseModel":
            return True
        if isinstance(base, ast.Attribute) and base.attr == "BaseModel":
            return True
    return False


def _end_line(node) -> int:
    return getattr(node, "end_lineno", None) or max(
        (getattr(n, "lineno", node.lineno) for n in ast.walk(node)), default=node.lineno
    )
