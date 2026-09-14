# oedipus-vulnapp — the project's own target

A small multi-tenant "Acme Notes" SaaS (FastAPI + Jinja2/HTMX) built to be
scanned. Unlike the vendored benchmarks, every bug here is planted on purpose
and mapped 1:1 to an Oedipus check, so `oedipus eval vulnapp` has frozen ground
truth that we fully control.

Source: [`vulnapp/app.py`](../vulnapp/app.py). Ground truth:
[`benchmarks/expected/vulnapp.json`](../benchmarks/expected/vulnapp.json).

## Two builds

| Build | Env | Port | Purpose |
|---|---|---|---|
| vulnerable | `VULNAPP_SAFE=0` | 8000 | the scored target |
| hardened | `VULNAPP_SAFE=1` | 8001 | false-positive control — must yield **zero** findings |

Because we own the app, the hardened build fixes *all* bugs, so the entire check
set is used for the FP control (VAmPI's `vulnerable=0` only toggles some).

## Planted bugs (must detect)

| Check | Endpoint | Bug | Hardened build |
|---|---|---|---|
| `sqli` | `GET /api/products/search` | `q` string-concatenated into a `LIKE` clause → error-based SQLi | parameterized query (`?`) |
| `exposure` | `GET /api/debug/users` | dumps every user's cleartext password + api token | endpoint removed (404) |
| `mass_assignment` | `POST /api/register` | binds `admin` straight from the request body | ignores `admin`, forces `false` |
| `bola` | `GET /api/notes/{note_id}` | no object-level ownership check; any user reads any note | enforces per-object owner check (403) |
| `jwt` (weak) | `POST /api/login` | HS256 signed with `changeme` (in `payloads/jwt-secrets.txt`) | long random per-process secret |
| `jwt` (alg=none) | `GET /api/me` | decodes without verifying the signature → unsigned token accepted | pins HS256, verifies signature (401) |
| `ssrf` | `POST /api/url-preview` | fetches an attacker URL with no egress control, reflects the body | egress allowlist (400) |

The SSRF sink is pointed at an internal metadata mock
(`GET /internal/latest/meta-data/`, kept out of the OpenAPI schema so it is only
reachable *through* the sink), standing in for AWS IMDS at `169.254.169.254`.

## Negative "lookalike" routes (must NOT fire)

These prove the scanner doesn't cry wolf on safe code that resembles the bugs:

| Route | Safe pattern |
|---|---|
| `GET /api/products/{product_id}` | parameterized query — injecting quotes yields no DB error |
| `POST /api/url-preview-safe` | egress allowlist enforced in *both* builds |

Both are probed during `eval`; either one firing would show up as a false
positive (precision < 1.0), which is exactly the regression this guards against.

## Result

```
precision 1.00 · recall 1.00 · F1 1.00 · 7/7 TP · 0 FP · 0 safe-target FP
```

Reproduced by `tests/integration/test_against_vulnapp.py`, which boots both
builds as subprocesses and asserts the numbers above.
