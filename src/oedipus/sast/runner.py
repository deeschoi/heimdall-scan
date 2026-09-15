"""Shell out to Semgrep and return its raw JSON results."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any


class SastError(RuntimeError):
    """Semgrep is missing, mis-configured, or failed to run."""


def run_semgrep(rules_dir: str, src_dir: str, timeout: int = 300) -> list[dict[str, Any]]:
    if shutil.which("semgrep") is None:
        raise SastError(
            "semgrep is not installed. Install it with `pip install oedipus[sast]` "
            "(or `pip install semgrep`) to use `oedipus sast`."
        )
    cmd = ["semgrep", "--config", rules_dir, "--json", "--quiet", "--metrics=off", src_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SastError(f"semgrep timed out after {timeout}s") from exc
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SastError(
            f"semgrep failed (exit {proc.returncode}): {proc.stderr.strip() or 'no output'}"
        ) from exc
    errors = doc.get("errors") or []
    if errors:
        raise SastError(f"semgrep reported errors: {errors}")
    return doc.get("results", [])
