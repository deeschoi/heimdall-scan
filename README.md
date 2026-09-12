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
| **VAmPI** (`:5001` vuln / `:5002` safe) | fully wired + scored | precision 1.00 · recall 1.00 · F1 1.00 · 5/5 TP · 0 FP · 0 safe-FP |
| **crAPI** (`:8888`) | scaffolded; needs OTP-signup auth wired in | ground truth unscored until reproduced |
| **Juice Shop** (`:3000`) | optional breadth/demo target | not a scored suite |

## Install

```bash
make install          # venv + editable install
source .venv/bin/activate
```

## Quickstart

```bash
make bench-up         # docker compose: VAmPI vuln+safe (+ Juice Shop)
make bench-seed       # VAmPI ships an empty DB; GET /createdb seeds it
oedipus list-checks   # what Oedipus detects, with CWE/OWASP-API/WSTG/ASVS
oedipus eval vampi    # precision / recall / F1 vs benchmarks/expected/vampi.json
```

Scan and export:

```bash
oedipus scan --suite vampi --format md                 # human report
oedipus scan --suite vampi --format sarif --out o.sarif # GitHub Code Scanning
oedipus scan --suite vampi --format json --out o.json  # machine / baseline
oedipus replay o.json                                  # re-confirm each finding
oedipus explain o.json <fingerprint>                   # evidence for one finding
```

## Checks

| id | vuln | CWE | OWASP API | WSTG |
|---|---|---|---|---|
| `bola` | Broken object level authorization (IDOR) | CWE-639 | API1:2023 | WSTG-ATHZ-04 |
| `jwt` | Weak secret / `alg=none` | CWE-347 | API2:2023 | WSTG-SESS-10 |
| `exposure` | Excessive data exposure | CWE-200 | API3:2023 | WSTG-ATHZ-04 |
| `mass_assignment` | Privilege escalation via mass assignment | CWE-915 | API6:2023 | WSTG-BUSL-08 |
| `ssrf` | Server-side request forgery | CWE-918 | API7:2023 | WSTG-INPV-19 |
| `sqli` | Error-based SQL injection | CWE-89 | API8:2023 | WSTG-INPV-05 |

## Safety (see `docs/threat-model.md`)

- **Scope allowlist** — only loopback/RFC1918 by default; public targets require `--i-understand`.
- **No destructive methods** — `PUT/DELETE/PATCH` blocked unless `--unsafe`.
- **Rate limited** — `--rate-limit` (default 20 rps).

## Layout

```
src/oedipus/          scanner: models, http client, scope, crawler, auth, checks, report, eval
benchmarks/           compose.yml, suites/*.yaml, expected/*.json, payloads/*.txt
docs/                 training.md, threat-model.md, checks/*.md
tests/                unit oracles + a live VAmPI regression test (auto-skips if down)
.github/workflows/    eval.yml — boots targets, gates on recall/FP, uploads SARIF
```

## Adding a benchmark

1. Run the target in Docker; add a service to `benchmarks/compose.yml`.
2. Write `benchmarks/suites/<name>.yaml` (target, auth, checks, hints).
3. Reproduce each bug by hand; record it in `benchmarks/expected/<name>.json`
   (`must_detect: true` only for what you personally confirmed).
4. `oedipus eval <name>`.
