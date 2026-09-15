# Contributing a check

Every finding must come from a deterministic oracle — a matcher that looks at
a real response and decides yes/no. There is no scoring, no heuristic
confidence, no LLM in this loop. If you can't write a rule that says "this
response proves the bug," it isn't ready to be a `Check`.

## 1. Pick the identifiers up front

Before writing code, assign:

- **CWE** — the underlying weakness (e.g. `CWE-639` for BOLA).
- **OWASP API Top 10 (2023)** — e.g. `API1:2023`.
- **WSTG** — the OWASP Web Security Testing Guide id, e.g. `WSTG-ATHZ-04`.
- **ASVS** (optional but preferred) — e.g. `5.1.2`.
- **CVSS 3.1 vector** — score the bug as if it were real on a typical target.

These four/five fields are mandatory `Check` class attributes (see any file
in `src/oedipus/checks/` for the pattern) and appear in every report format
(Markdown, SARIF, JSON), so get them right — they're what a reader uses to
triage the finding.

## 2. Implement the `Check`

Subclass `oedipus.checks.Check` in a new module under `src/oedipus/checks/`:

```python
from oedipus.checks import Check, ScanContext, register
from oedipus.models import Finding, Severity

@register
class MyCheck(Check):
    id = "my_check"
    title = "..."
    cwe = "CWE-..."
    owasp_api = "API...:2023"
    wstg = "WSTG-..."
    asvs = "..."
    cvss_vector = "CVSS:3.1/..."

    def run(self, ctx: ScanContext) -> list[Finding]:
        ...
```

- `ctx.extras` carries suite-specific hints (e.g. `hints.mass_assignment` in
  a suite YAML) — keep target-specific knowledge in the suite, not the check.
  Look at `mass_assignment.py`'s docstring for the create/confirm hint shape.
- `ctx.client` is the shared `HttpClient`; use `ctx.client.evidence_from(resp,
  matcher=...)` to attach the request/response pair that makes the finding
  replayable. The `matcher` string should say *why* this response proves the
  bug — it's what a human reads in the report.
- Swallow connection/parsing errors and return no finding rather than
  raising — a broken probe is silence, not a crash.
- Register the module in `load_builtin_checks()` in
  `src/oedipus/checks/__init__.py`.
- Implement `replay()`/`oracle()` if the default re-request-and-reoracle
  behavior in the base class isn't enough (most checks don't need to
  override it).

## 3. Write the unit tests

Add `tests/checks/test_<id>.py` using `respx` to mock the target (see
`tests/checks/test_mass_assignment.py` for the fullest example). Cover, at
minimum:

- The vulnerable case fires exactly one finding with the right
  `check_id`/`severity`/`cwe`/`owasp_api`/`method`/`path_template`, and the
  evidence needed to explain the finding.
- The fixed/lookalike case (parameterized query, allowlisted fetch, schema
  that drops the extra field, etc.) produces **zero** findings — this is
  your contribution to the false-positive-control story.
- Any oracle helper function has its own direct unit tests (edge cases:
  non-JSON bodies, nested structures, unrelated matches).
- Unreachable/erroring probe steps fail silently, not with an exception.

## 4. Add ground truth

For each suite where the new check applies:

1. Reproduce the bug by hand against the running target.
2. Add a row to `benchmarks/expected/<suite>.json`:

   ```json
   {
     "id": "<suite>-<check>-<slug>",
     "check": "my_check",
     "method": "GET",
     "path": "/exact/path/template",
     "cwe": "CWE-...",
     "owasp_api": "API...:2023",
     "wstg": "WSTG-...",
     "must_detect": true,
     "note": "Confirmed <date>: <exact repro steps — request, response, why it proves the bug>."
   }
   ```

3. Only set `must_detect: true` for what you personally reproduced — that's
   what keeps `oedipus eval`'s recall number honest. Leave `must_detect:
   false` placeholder rows commented with what's still unverified rather
   than guessing.
4. If the suite has a hardened/safe build (like `vulnapp`'s
   `VULNAPP_SAFE=1`), confirm the new check produces zero findings there too
   — add it to the suite's `safe_checks` list if it isn't already covered.
5. Run `oedipus eval <suite>` and confirm precision/recall/F1.

## 5. Add a lookalike route (if you're also touching `vulnapp/`)

Every planted bug in `vulnapp/` has a negative counterpart that looks similar
but is safe (parameterized SQL next to the raw-concatenated query, an
allowlisted fetch next to the SSRF-able one). If your check targets a new bug
class, add both the vulnerable route and its safe lookalike so the
zero-false-positive claim keeps meaning something.

## Style notes

- No comments explaining *what* the code does — names should do that.
  Comment only non-obvious *why* (a workaround, an invariant, a subtlety in
  the oracle).
- Don't add configuration, feature flags, or generality the check doesn't
  need yet. A `Check` for one specific vulnerability class, backed by one
  deterministic oracle, is the whole unit.
