"""semgrep is run from an absolute PATH entry, never from the current folder (F14)."""

import os
import stat

import pytest

from heimdall.sast import runner
from heimdall.sast.runner import SastError, resolve_semgrep


def _exe(folder, name="semgrep"):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text("#!/bin/sh\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def test_relative_and_empty_path_entries_are_skipped(tmp_path, monkeypatch):
    planted = _exe(tmp_path / "repo")
    trusted = _exe(tmp_path / "bin")
    monkeypatch.chdir(tmp_path / "repo")
    monkeypatch.delenv("HEIMDALL_SEMGREP", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tmp_path / "bin")]))
    assert resolve_semgrep() == str(trusted)
    assert resolve_semgrep() != str(planted)


def test_semgrep_only_in_current_folder_is_not_found(tmp_path, monkeypatch):
    _exe(tmp_path / "repo")
    monkeypatch.chdir(tmp_path / "repo")
    monkeypatch.delenv("HEIMDALL_SEMGREP", raising=False)
    monkeypatch.setenv("PATH", ".")
    with pytest.raises(SastError, match="not installed"):
        resolve_semgrep()


def test_override_must_be_absolute(monkeypatch):
    monkeypatch.setenv("HEIMDALL_SEMGREP", "semgrep.exe")
    with pytest.raises(SastError, match="relative"):
        resolve_semgrep()


def test_run_semgrep_invokes_the_resolved_absolute_path(tmp_path, monkeypatch):
    trusted = _exe(tmp_path / "bin")
    monkeypatch.delenv("HEIMDALL_SEMGREP", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    seen = {}

    class Done:
        stdout = '{"results": []}'
        stderr = ""
        returncode = 0

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return Done()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner.run_semgrep("rules", "src")
    assert seen["cmd"][0] == str(trusted)
