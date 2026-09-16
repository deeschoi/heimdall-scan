from heimdall.sast.routes import build_index

_SOURCE = '''
from fastapi import FastAPI
from pydantic import BaseModel


class RegisterIn(BaseModel):
    username: str
    admin: bool = False


def create_app():
    app = FastAPI()

    @app.post("/api/register")
    def register(payload: RegisterIn):
        return payload

    @app.get("/api/notes/{note_id}")
    def read_note(note_id: str):
        return note_id

    return app
'''


def _write(tmp_path, name="app.py"):
    p = tmp_path / name
    p.write_text(_SOURCE)
    return p


def test_resolves_line_inside_route_body(tmp_path):
    p = _write(tmp_path)
    index = build_index(str(tmp_path))
    # "return note_id" is inside read_note's body.
    line = next(i for i, l in enumerate(_SOURCE.splitlines(), 1) if "return note_id" in l)
    assert index.resolve(str(p), line) == ("GET", "/api/notes/{note_id}")


def test_resolves_line_inside_model_via_route_param_type(tmp_path):
    p = _write(tmp_path)
    index = build_index(str(tmp_path))
    line = next(i for i, l in enumerate(_SOURCE.splitlines(), 1) if "admin: bool" in l)
    assert index.resolve(str(p), line) == ("POST", "/api/register")


def test_unresolvable_line_returns_none(tmp_path):
    p = _write(tmp_path)
    index = build_index(str(tmp_path))
    line = next(i for i, l in enumerate(_SOURCE.splitlines(), 1) if "import FastAPI" in l)
    assert index.resolve(str(p), line) is None


def test_skips_files_that_fail_to_parse(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    _write(tmp_path)
    index = build_index(str(tmp_path))
    assert len(index.routes) == 2
