"""Accidental (not planted) vulnapp flaws stay fixed in both builds.

F6: a note id owned by someone else cannot be taken over.
F11: /ui/notes lists only the caller's own notes, and nothing without a login.
F22: the SQLite file lives in a private, unpredictable folder.
"""

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("fastapi", reason="vulnapp extra not installed")

from fastapi.testclient import TestClient  # noqa: E402

import vulnapp.app as vapp  # noqa: E402


@pytest.fixture(params=[False, True], ids=["vulnerable", "hardened"])
def client(request, monkeypatch):
    monkeypatch.setattr(vapp, "SAFE", request.param)
    monkeypatch.setattr(vapp, "JWT_SECRET", vapp.STRONG_JWT_SECRET if request.param else vapp.WEAK_JWT_SECRET)
    return TestClient(vapp.create_app())


def _login(client, username, password):
    client.post("/api/register", json={"username": username, "password": password})
    token = client.post("/api/login", json={"username": username, "password": password}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_note_id_owned_by_another_user_cannot_be_overwritten(client):
    mallory = _login(client, "mallory", "pw-mallory-1")
    resp = client.post("/api/notes", json={"id": "welcome", "title": "pwned"}, headers=mallory)
    assert resp.status_code == 409
    alice = {"Authorization": "Bearer " + vapp._issue_token(vapp._USERS["alice"])}
    note = client.get("/api/notes/welcome", headers=alice).json()
    assert note["owner"] == "alice" and note["title"] == "Welcome"


def test_owner_can_still_update_their_own_note(client):
    user = _login(client, "dave", "pw-dave-1")
    assert client.post("/api/notes", json={"id": "n1", "title": "v1"}, headers=user).status_code == 200
    assert client.post("/api/notes", json={"id": "n1", "title": "v2"}, headers=user).json()["title"] == "v2"


def test_ui_notes_lists_nothing_without_a_login(client):
    page = client.get("/ui/notes").text
    assert "Welcome" not in page and "alice" not in page and "acme" not in page


def test_ui_notes_lists_only_the_callers_notes(client):
    user = _login(client, "erin", "pw-erin-1")
    client.post("/api/notes", json={"id": "erin-1", "title": "erins plan"}, headers=user)
    page = client.get("/ui/notes", headers=user).text
    assert "erins plan" in page
    assert "Welcome" not in page


def test_home_page_does_not_embed_notes(client):
    assert "Internal onboarding" not in client.get("/").text


def test_database_lives_in_a_private_folder():
    folder = vapp.DB_PATH.parent
    assert folder.name.startswith("vulnapp-")
    if os.name == "posix":
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
