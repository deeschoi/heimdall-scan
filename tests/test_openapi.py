from heimdall.crawler import parse_endpoints, fill_path

SPEC = {
    "paths": {
        "/users/v1/{username}": {
            "get": {
                "summary": "get user",
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ],
            }
        },
        "/books/v1": {
            "get": {"summary": "list"},
            "post": {
                "summary": "add",
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
            },
        },
    }
}


def test_parse_endpoints_counts_operations():
    eps = parse_endpoints(SPEC)
    keys = {(e.method, e.path_template) for e in eps}
    assert ("GET", "/users/v1/{username}") in keys
    assert ("GET", "/books/v1") in keys
    assert ("POST", "/books/v1") in keys


def test_path_params_detected():
    eps = parse_endpoints(SPEC)
    user_get = next(e for e in eps if e.path_template == "/users/v1/{username}")
    assert [p.name for p in user_get.path_params] == ["username"]


def test_request_body_schema_captured():
    eps = parse_endpoints(SPEC)
    post = next(e for e in eps if e.method == "POST")
    assert post.request_body_schema == {"type": "object"}


def test_fill_path():
    assert fill_path("/users/v1/{username}", {"username": "admin'"}) == "/users/v1/admin'"
