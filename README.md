# Oedipus

An API-focused DAST CLI where **every finding is a deterministic, replayable
check**. Exploration can be heuristic (and later LLM-assisted), but a finding is
only emitted when a matcher fires and its evidence request can be replayed.

Detection quality is a *measured* claim: `oedipus eval` scores the scanner
against frozen ground truth on deliberately-vulnerable benchmarks (VAmPI, crAPI)
and checks a `vulnerable=0` control target produces zero findings.

## Current status

| Target | State | Result |
|---|---|---|
| **oedipus-vulnapp** (`:8000` vuln / `:8001` hardened) | this repo's OWN target ([`vulnapp/`](vulnapp/)) | precision 1.00 · recall 1.00 · F1 1.00 · 7/7 TP · 0 FP · 0 safe-FP |
| **VAmPI** (`:5001` vuln / `:5002` safe) | fully wired + scored | precision 1.00 · recall 1.00 · F1 1.00 · 5/5 TP · 0 FP · 0 safe-FP |
| **crAPI** (`:8888`) | fully wired + scored | precision 1.00 · recall 1.00 · F1 1.00 · 4/4 TP · 0 FP |
| **Juice Shop** (`:3000`) | optional breadth/demo target | not a scored suite |

`oedipus-vulnapp` is a small multi-tenant notes SaaS (FastAPI + Jinja2/HTMX UI,
`/openapi.json` contract) with six bugs planted on purpose — one per check — plus
negative "lookalike" routes (parameterized SQL, allowlisted fetch) that must
**not** fire. A hardened build (`VULNAPP_SAFE=1`) fixes every bug, so the whole
check set is used for the zero-false-positive control.

## Demo

`list-checks` → `eval` (scored against frozen ground truth) → `scan` (the
Markdown report), run against the project's own `vulnapp` target:

```bash
asciinema play docs/demo/oedipus-demo.cast   # recorded with docs/demo/record.sh
```

<details>
<summary>Transcript (click to expand)</summary>

```
$ oedipus list-checks
                                           Oedipus checks
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ id              ┃ title                            ┃ CWE     ┃ OWASP API ┃ WSTG         ┃ ASVS   ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━┩
│ bola            │ Broken object level              │ CWE-639 │ API1:2023 │ WSTG-ATHZ-04 │ 4.2.1  │
│                 │ authorization (IDOR)             │         │           │              │        │
│ exposure        │ Excessive data exposure of       │ CWE-200 │ API3:2023 │ WSTG-ATHZ-04 │ 8.3.4  │
│                 │ sensitive fields                 │         │           │              │        │
│ jwt             │ Weak or forgeable JWT            │ CWE-347 │ API2:2023 │ WSTG-SESS-10 │ 3.5.3  │
│ mass_assignment │ Mass assignment enables          │ CWE-915 │ API6:2023 │ WSTG-BUSL-08 │ 5.1.2  │
│                 │ privilege escalation             │         │           │              │        │
│ sqli            │ Error-based SQL injection        │ CWE-89  │ API8:2023 │ WSTG-INPV-05 │ 5.3.4  │
│ ssrf            │ Server-side request forgery      │ CWE-918 │ API7:2023 │ WSTG-INPV-19 │ 12.6.1 │
└─────────────────┴──────────────────────────────────┴─────────┴───────────┴──────────────┴────────┘

$ oedipus eval vulnapp
         eval: vulnapp
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ metric          ┃ value     ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ precision       │ 1.000     │
│ recall          │ 1.000     │
│ f1              │ 1.000     │
│ TP / FP / FN    │ 7 / 0 / 0 │
│ safe-target FPs │ 0         │
└─────────────────┴───────────┘

$ oedipus scan --suite vulnapp --format md --out /tmp/oedipus-demo.md
Wrote 7 findings to /tmp/oedipus-demo.md
7 findings (critical=1, high=6)

# Oedipus scan report

**Target:** `http://127.0.0.1:8000`
**Findings:** 7

| Severity | Check | Endpoint | CWE | OWASP API | WSTG |
|---|---|---|---|---|---|
| CRITICAL | `jwt` | `GET /api/me` | CWE-347 | API2:2023 | WSTG-SESS-10 |
| HIGH | `sqli` | `GET /api/products/search` | CWE-89 | API8:2023 | WSTG-INPV-05 |
| HIGH | `exposure` | `GET /api/debug/users` | CWE-200 | API3:2023 | WSTG-ATHZ-04 |
| HIGH | `mass_assignment` | `POST /api/register` | CWE-915 | API6:2023 | WSTG-BUSL-08 |
| HIGH | `bola` | `GET /api/notes/{note_id}` | CWE-639 | API1:2023 | WSTG-ATHZ-04 |
| HIGH | `jwt` | `POST (login)` | CWE-347 | API2:2023 | WSTG-SESS-10 |
| HIGH | `ssrf` | `POST /api/url-preview` | CWE-918 | API7:2023 | WSTG-INPV-19 |

## CRITICAL — JWT 'alg=none' accepted on a protected endpoint

- **Check:** `jwt` (`95b0292b6b59`)
- **Endpoint:** `GET /api/me`
- **CWE:** CWE-347 · **OWASP API:** API2:2023 · **WSTG:** WSTG-SESS-10 · **ASVS:** 3.5.3
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

An unsigned token was accepted, allowing trivial impersonation.

**Remediation:** Pin an allowlist of signing algorithms; reject 'none'.

<details><summary>Evidence #1: alg=none token accepted (HTTP 200)</summary>

...
```

</details>

To re-record after a UI/output change: bring up `vulnapp` on `:8000`/`:8001`
(see Quickstart below), then `./docs/demo/record.sh` on its own to preview,
or wrap it with `asciinema rec` per the header comment in that script.

## Install

```bash
make install          # venv + editable install (includes the vulnapp extra)
source .venv/bin/activate
```

## Quickstart (the project's own target — no Docker required)

```bash
# start both builds locally
PORT=8000 VULNAPP_SAFE=0 python -m vulnapp &   # vulnerable  -> http://127.0.0.1:8000
PORT=8001 VULNAPP_SAFE=1 python -m vulnapp &   # hardened    -> http://127.0.0.1:8001

oedipus list-checks                # what Oedipus detects (CWE/OWASP-API/WSTG/ASVS)
oedipus eval vulnapp               # precision / recall / F1 + safe-target FP scan
oedipus scan --suite vulnapp --format md
```

Open <http://127.0.0.1:8000> to see the app in a browser; Oedipus scans the
`/openapi.json` contract, not the HTML. (Docker alternative: `make vulnapp-up`.)

## Benchmarks (VAmPI)

```bash
make bench-up         # docker compose: VAmPI vuln+safe (+ Juice Shop)
make bench-seed       # VAmPI ships an empty DB; GET /createdb seeds it
oedipus eval vampi    # precision / recall / F1 vs benchmarks/expected/vampi.json
```

Scan and export:

```bash
oedipus scan --suite vampi --format md                 # human report
oedipus scan --suite vampi --format sarif --out o.sarif # GitHub Code Scanning
oedipus scan --suite vampi --format json --out o.json  # machine / baseline
oedipus replay o.json                                  # re-confirm each finding
oedipus explain o.json <fingerprint>                   # evidence for one finding
oedipus gate o.json --accepted-risk accepted-risk.yml --fail-on high
```

## Benchmarks (crAPI)

crAPI's own stack (`crAPI-main/deploy/docker`) is heavier than VAmPI's — it's a
multi-service microservice app with email/OTP signup via MailHog — so it isn't
wired into `benchmarks/compose.yml`. Bring it up with crAPI's own compose file,
then:

```bash
oedipus eval crapi    # precision / recall / F1 vs benchmarks/expected/crapi.json
oedipus scan --suite crapi --format md
```

Ground truth in `benchmarks/expected/crapi.json` (BOLA on vehicle location,
BOLA on mechanic reports, SSRF via `contact_mechanic`, and a forged `alg=none`
JWT) was reproduced by hand against a running stack; see the file's per-row
notes for exact repro steps.

## Checks

| id | vuln | CWE | OWASP API | WSTG |
|---|---|---|---|---|
| `bola` | Broken object level authorization (IDOR) | CWE-639 | API1:2023 | WSTG-ATHZ-04 |
| `jwt` | Weak secret / `alg=none` | CWE-347 | API2:2023 | WSTG-SESS-10 |
| `exposure` | Excessive data exposure | CWE-200 | API3:2023 | WSTG-ATHZ-04 |
| `mass_assignment` | Privilege escalation via mass assignment | CWE-915 | API6:2023 | WSTG-BUSL-08 |
| `ssrf` | Server-side request forgery | CWE-918 | API7:2023 | WSTG-INPV-19 |
| `sqli` | Error-based SQL injection | CWE-89 | API8:2023 | WSTG-INPV-05 |

## SAST + correlate

`oedipus sast` runs a small set of custom Semgrep rules (`semgrep-rules/`)
over source and emits findings in the **same** `Finding` schema as `scan` —
same reporters, same `oedipus gate`. `oedipus correlate` then joins a SAST
report and a DAST report on `(method, path_template, cwe)`, since the two
layers speak different check-id vocabularies but agree on CWE:

```bash
pip install -e ".[sast]"          # installs the real semgrep binary
oedipus sast --rules semgrep-rules --src vulnapp --format json --out sast.json
oedipus scan --suite vulnapp --format json --out dast.json
oedipus correlate --dast dast.json --sast sast.json --format md
```

Run against `vulnapp/app.py`, this correlates 3 of the 6 planted bugs (SQLi,
mass assignment, SSRF) — one alert instead of two duplicate ones. The other
three are informative on their own:

- **BOLA and excessive data exposure are DAST-only.** Both require reasoning
  about runtime state (does this caller own this object? does this dict
  actually contain a password field?) that a syntactic source scan can't do.
  JWT's weak-secret/`alg=none` bugs are flagged by SAST too, but at the
  token life-cycle code itself rather than a single route — a shared auth
  helper is cross-cutting, so it shows up as `sast_only` rather than joined.
- **SSRF is flagged at *both* url-preview routes by SAST**, including the
  hardened `/api/url-preview-safe` lookalike — the allowlist check that
  protects it lives in the *caller*, not the sink function itself, which a
  syntactic rule can't see. DAST resolves the ambiguity by actually testing
  both routes at runtime. This is the concrete case for running both layers:
  SAST tells you where a sink is reachable from user input; DAST tells you
  whether the guard in front of it actually holds.

## Safety (see `docs/threat-model.md`)

- **Scope allowlist** — only loopback/RFC1918 by default; public targets require `--i-understand`.
- **No destructive methods** — `PUT/DELETE/PATCH` blocked unless `--unsafe`.
- **Rate limited** — `--rate-limit` (default 20 rps).

## Layout

```
src/oedipus/          scanner: models, http client, scope, crawler, auth, checks, report, eval
src/oedipus/sast/     Semgrep runner + AST route mapper, emits the same Finding schema
src/oedipus/correlate.py  join a SAST report + a DAST report on (method, path, cwe)
semgrep-rules/        custom rules for oedipus sast (sqli, ssrf, jwt, mass assignment)
vulnapp/              the project's OWN vulnerable target (FastAPI + Jinja2/HTMX, SAFE-mode toggle)
benchmarks/           compose.yml, suites/*.yaml, expected/*.json, payloads/*.txt
docs/                 training.md, threat-model.md, vulnapp.md, checks/*.md
tests/                unit oracles + live regressions (VAmPI + vulnapp; auto-skip if unavailable)
.github/workflows/    ci.yml (pytest) + scan.yml (eval gate, SARIF, PR baseline, accepted-risk)
accepted-risk.yml     finding fingerprint + owner + expiry; consumed by `oedipus gate`
```

## CI

- **`.github/workflows/ci.yml`** — install deps, run `pytest` (unit + in-process vulnapp integration).
- **`.github/workflows/scan.yml`** — `docker compose up` for vulnapp and VAmPI, `oedipus eval --min-recall 1.0 --max-fp 0`, upload SARIF to GitHub Code Scanning, then `oedipus gate --fail-on high`. Also runs `oedipus sast` + `oedipus correlate` against vulnapp and uploads the reports as artifacts (informational — not yet gated).
- **PR-only** — download `main`'s last JSON report and pass it as `--baseline` so only **new** High+ findings fail the PR.
- **`accepted-risk.yml`** — planted demo findings are tracked (fingerprint, owner, expiry) and suppressed from the fail-on gate until they expire. Code Scanning still gets the unfiltered SARIF.

```bash
oedipus scan --suite vulnapp --format json --out vulnapp.json
oedipus gate vulnapp.json --accepted-risk accepted-risk.yml --fail-on high
oedipus gate vulnapp.json --baseline prior.json --fail-on high   # PR delta
```

## Adding a benchmark

1. Run the target in Docker; add a service to `benchmarks/compose.yml`.
2. Write `benchmarks/suites/<name>.yaml` (target, auth, checks, hints).
3. Reproduce each bug by hand; record it in `benchmarks/expected/<name>.json`
   (`must_detect: true` only for what you personally confirmed).
4. `oedipus eval <name>`.
