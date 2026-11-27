"""Shell out to Semgrep and return its raw JSON results."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Optional


class SastError(RuntimeError):
    """Semgrep is missing, mis-configured, or failed to run."""


def _candidates(name: str) -> list[str]:
    if os.name != "nt":
        return [name]
    exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    return [name + e.lower() for e in exts] + [name + e for e in exts]


def _which_on_path(name: str) -> Optional[str]:
    """Find ``name`` in the absolute PATH entries only.

    Unlike a bare program name handed to the OS (and ``shutil.which`` on older
    Pythons on Windows), this never looks in the current folder, and skips
    empty or relative PATH entries, which also mean "the current folder".
    """
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        for cand in _candidates(name):
            full = os.path.join(entry, cand)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    return None


def resolve_semgrep() -> str:
    """Absolute path of the semgrep executable to run.

    ``HEIMDALL_SEMGREP`` names it explicitly; otherwise it is the first match
    in the absolute PATH entries. The current folder -- often the untrusted
    tree being scanned -- is never searched.
    """
    exe = os.environ.get("HEIMDALL_SEMGREP") or _which_on_path("semgrep")
    if exe is None:
        raise SastError(
            "semgrep is not installed. Install it with `pip install heimdall[sast]` "
            "(or `pip install semgrep`) to use `heimdall sast`."
        )
    if not os.path.isabs(exe):
        raise SastError(
            f"refusing to run semgrep from relative path {exe!r}; "
            "set HEIMDALL_SEMGREP to an absolute path."
        )
    return exe


def run_semgrep(rules_dir: str, src_dir: str, timeout: int = 300) -> list[dict[str, Any]]:
    exe = resolve_semgrep()
    cmd = [exe, "--config", rules_dir, "--json", "--quiet", "--metrics=off", src_dir]
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
