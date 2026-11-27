# Security remediation plan

Source: Claude Security scan of 2026-11-25 (`CLAUDE-SECURITY-20261125-140712/CLAUDE-SECURITY-RESULTS.md`),
24 verified findings at commit `cfd950d`. Work happens on branch `security-remediation`.

## Guiding decisions

1. **Planted vulnapp bugs stay planted.** F1 (debug dump), F2 (unsigned JWT), F3/F29 (SSRF),
   F4/F26 (SQLi) and F5/F27/F28 (BOLA read) are the ground truth that `heimdall eval vulnapp`
   scores against. They are already listed in `accepted-risk.yml`, and the hardened build already
   fixes them. Removing them would break recall. They get **containment** instead: bind to
   loopback (Phase 5, F9).
2. **The hardened build must be really hardened.** It is the zero-false-positive control, so every
   flaw still present with `VULNAPP_SAFE=1` (F6, F11) is a bug in the control and gets fixed.
3. **Fix each class once, centrally.** Nine of the scanner findings are one bug: target-controlled
   text printed or rendered without escaping. One sanitizer plus a renderer fix closes all of them.
4. **Every fix lands with a regression test**, and each phase ends with the eval gates green:
   `heimdall eval vulnapp` and `heimdall eval vampi` at precision/recall 1.00 and 0 safe-target FPs.

## Phase overview

| Phase | Theme | Findings | Severity | Effort |
|---|---|---|---|---|
| 1 | Transport and scope integrity | F7, F18, F17/F44, F12 | MEDIUM–LOW | M |
| 2 | Secret hygiene in evidence | F8, F13 | MEDIUM | S |
| 3 | Untrusted text to terminal and Markdown | F10, F15/F38, F16, F19, F20, F21, F23, F24 | MEDIUM–LOW | M |
| 4 | SAST subprocess | F14 | MEDIUM (Windows only) | XS |
| 5 | vulnapp and benchmarks | F9, F6, F11/F31, F22 | MEDIUM–LOW | S |
| 6 | Verify and close out | 3 unfollowed leads, rescan | — | S |

Phases 1 and 2 come first because they break promises that README and `docs/threat-model.md` make
to operators (TLS verified unless `--insecure`; credentials never in reports; nothing outside
named scope gets traffic). Phase 3 is the broadest change. Phases 4 and 5 are small and can run
in parallel with anything.

---

## Phase 1 — Transport and scope integrity

### F7 — OpenAPI spec fetched with `verify=False`, outside scope and rate limit
- **Where:** `src/heimdall/crawler/openapi.py:49` (`load_spec`); only caller `src/heimdall/engine.py:75`.
- **Change:**
  - `load_spec(source, client: HttpClient | None)`: when it is a URL and no client is given, raise
    instead of building a private `httpx.Client(verify=False)`.
  - `engine._load_endpoints` takes the scan's `HttpClient` and passes it, so the spec fetch is
    scope-checked, rate-limited, and honours `--insecure`. This means opening the `HttpClient`
    before loading endpoints in `scan()` / `scan_suite()`.
  - `iter_specs` gets the same treatment, or is removed if unused.
- **Tests:** `tests/test_openapi.py`. A spec URL on an out-of-scope host raises `ScopeError`.
  A mock transport records that `verify` follows `verify_tls`.

### F18 — Spec path concatenated into URL lets a hostile spec choose the port
- **Where:** `src/heimdall/checks/__init__.py:49` (`ScanContext.url`), `crawler/openapi.py:67`, `scope.py` `check`.
- **Change:**
  - `parse_endpoints`: drop (and warn on) any path key that does not start with `/`, or that
    contains `@`, `\`, `//` at the start, or control characters.
  - `ScanContext.url`: build the URL, then assert that scheme, host and port equal those of
    `base_url`. Otherwise raise `ScopeError`.
  - `Scope`: store `(host, port)` pairs from targets and `--scope` entries (a host with no port
    allows the scheme's default port and the port given explicitly). `check()` compares both.
- **Tests:** `test_openapi.py` (rejects `@127.0.0.1:2375/x`); `test_scope.py` (same host, other port is refused).

### F17 / F44 — Mixed private/public DNS or rebinding passes the public-host guard
- **Where:** `src/heimdall/scope.py:31-44` (`_is_private_host`).
- **Change, in two steps:**
  1. **Now:** treat a name as private only if **all** resolved addresses are private, loopback
     or link-local (`all()` not `any()`), and treat an empty resolution as not private.
  2. **Next:** pin. `validate()` records the vetted IPs per host, and `HttpClient` uses a custom
     httpx transport (or connects to the IP with `Host`/SNI set) so that the connection only goes
     to vetted addresses. Alternatively, check the peer address after connect and abort when it is
     not in the vetted set.
- **Tests:** `test_scope.py` with `socket.getaddrinfo` monkeypatched to return `[127.0.0.1, 203.0.113.10]`, which must be refused without `--i-understand`.

### F12 — `replay` derives scope from the report file
- **Where:** `src/heimdall/cli.py:201` (`replay`), `checks/__init__.py` `Check.replay`.
- **Change:**
  - `replay` requires `--target` (repeatable) and/or `--scope`. Scope is built **only** from those.
    Findings whose `url` or `evidence[0].request_url` (host and port) fall outside it are reported
    `OUT-OF-SCOPE` and skipped.
  - `Check.replay` drops `Host`, `Content-Length`, `Transfer-Encoding`, `Connection` and other
    hop-by-hop headers from the stored evidence before resending.
  - Replace the method denylist with an allowlist: GET/HEAD/OPTIONS by default, POST only with
    `--allow-post` (or `--unsafe`), and refuse non-standard methods unless `--unsafe` is set.
    Apply the same allowlist in `HttpClient.request`.
  - Update README line ~217 and the `replay` usage examples.
- **Tests:** `tests/test_cli_trace.py` or a new `tests/test_replay.py`. A report pointing at
  `127.0.0.1:2375` with no `--target` exits with an error. A report with `--target` set to another
  host skips the finding.

## Phase 2 — Secret hygiene in evidence

### F8 — Identity tokens in custom header names survive redaction
- **Where:** `src/heimdall/http_client.py:32` (`_request_headers`), `auth/__init__.py:66,104,112`.
- **Change:**
  - `HttpClient` gains `self.secret_headers: set[str]` and `self.secret_values: set[str]`.
    `build_identities` registers every header name and token value it injects
    (`client.register_secret(name, value)`).
  - `evidence_from` becomes an instance method (keep a static shim for tests) and redacts:
    the fixed list, plus registered names, plus a pattern
    (`token|key|secret|session|auth|password|cookie`, case-insensitive). It also masks registered
    **values** wherever they appear in request/response headers, body and URL (`[REDACTED]`).
  - Update callers in `checks/bola.py`, `checks/ssrf.py` and any others that call `HttpClient.evidence_from(resp)` statically.
- **Tests:** `test_http_client.py`. An identity with `header: X-Access-Token` produces evidence
  with no token in headers, URL or body.

### F13 — Basic-auth password in target URL is written into `request_url`
- **Where:** `src/heimdall/http_client.py:101`.
- **Change:**
  - At entry (`cli.scan_cmd`, `Suite.load`, `replay`), split userinfo off the target. Pass it as
    `httpx.BasicAuth` on the client, and keep a userinfo-free `base_url`.
  - Defence in depth in `evidence_from`: `req.url.copy_with(username=None, password=None)`.
  - Register the password as a secret value (F8 mechanism).
- **Tests:** `test_http_client.py`. Target `http://u:p@127.0.0.1` produces no `p` anywhere in `Finding.to_dict()`.

## Phase 3 — Untrusted text to terminal and Markdown

One root cause: target- or source-derived strings (response bodies, spec path keys, JWT `alg`,
route literals, report fields) reach Rich with markup on and/or ESC intact, and reach Markdown
without escaping.

### 3a. One sanitizer — new `src/heimdall/report/safe_text.py`
```python
def terminal_safe(s: str) -> str:
    """Escape C0/C1 controls (incl. ESC 0x1b and CSI 0x9b), keep \n and \t."""
def md_inline(s: str) -> str:
    """Make s safe inside `code` spans and table cells: escape `, |, newlines."""
def md_fence(content: str, info: str = "") -> str:
    """Fence longer than the longest backtick run in content."""
```

### 3b. Terminal sinks (F10, F15/F38, F16, F19, F20, F23, F24)
- Add a single `_print_report(text)` helper in `cli.py` that calls
  `console.print(terminal_safe(text), markup=False, highlight=False)`. Use it in `scan_cmd:147`,
  `sast_cmd:266`, `correlate_cmd:291` and `gate_cmd:321`.
- `replay` (`cli.py:218-229`) and `_print_eval` (`cli.py:355`): keep the coloured verdict markup,
  but wrap every report-derived field in `rich.markup.escape(terminal_safe(...))`.
- `report/trace.py`: apply `terminal_safe` to `event.text`, `path_template`, `method` and `cwe` in
  both `TraceLog._print` and `format_plain`.
- `checks/jwt.py:85`: trace `repr(alg)` instead of raw `alg`.

### 3c. Markdown renderer (F21)
- `report/markdown.py`: use `md_fence()` for the request and response blocks. Use `md_inline()`
  for `path_template`, `method`, `title`, `target`, `matcher` and `request_url` in the table, the
  Endpoint line and `<summary>`. HTML-escape `<` and `>` in free text, so `<!--` cannot hide the
  rest of the report.
- `report/trace.py` `markdown_section`: use `md_fence()`.
- Check `correlate.render` for the same pattern and apply the same helpers.

### Tests
- `tests/test_reporters.py`. A finding whose body contains a backtick fence followed by
  `**No issues found.**` and `<!--` keeps every later section visible, which you can check by
  parsing the fences. A `path_template` with `|` and a backtick keeps the table shape.
- `tests/test_trace.py` and `test_cli_trace.py`. Output captured from a body with
  `\x1b[2K\x1b]52;c;...\x07` contains no raw `\x1b`. A `path_template` of
  `[green]CONFIRMED[/green]` prints literally in `replay`.

## Phase 4 — SAST subprocess (F14)
- **Where:** `src/heimdall/sast/runner.py:23`.
- **Change:** `exe = shutil.which("semgrep", path=os.environ.get("PATH", ""))`. Refuse it if it is
  not absolute or if it is inside the current folder or `src_dir`, then run `[exe, ...]`. Allow an
  override with `HEIMDALL_SEMGREP=/abs/path`.
- **Tests:** `test_sast_mapping.py` or a new runner test. Monkeypatch `which` to return
  `.\semgrep.exe` and check that the run is refused.

## Phase 5 — vulnapp and benchmarks

### F9 — Vulnerable targets published on all interfaces
- `benchmarks/compose.yml`: change every mapping to loopback, for example `"127.0.0.1:8000:8000"`,
  `"127.0.0.1:8001:8000"`, `"127.0.0.1:5001:5000"`, `"127.0.0.1:5002:5000"`, `"127.0.0.1:3000:3000"`.
- Keep `HOST=0.0.0.0` in `vulnapp/Dockerfile`: it is needed inside the container, and the host
  binding is what matters. Add a comment saying so.
- Check that CI (`.github/workflows/scan.yml`) still reaches the services. It runs on the same host, so loopback works.

### F6 — Note overwrite by id (both builds)
- `vulnapp/app.py` `create_note` (~line 277-287). When `SAFE`, refuse with 409 or 403 if the id
  exists and belongs to another owner or tenant (or generate server-side ids).
- **Decide:** also plant it on purpose in the vulnerable build as a write-side BOLA? If yes, add it
  to `benchmarks/expected/vulnapp*.json`, `docs/vulnapp.md` and `accepted-risk.yml`. If no, fix it
  in both builds. Recommended: fix it in both, because the current behaviour is accidental, not planted.

### F11 / F31 — `/ui/notes` lists every tenant's notes without auth
- `vulnapp/app.py` `ui_notes` (~line 205). When `SAFE`, require a session (or show only notes
  marked public), and never show owner or tenant across tenants. Apply the same decision as F6
  about the vulnerable build.

### F22 — Predictable SQLite path in shared temp
- `vulnapp/app.py:56`. Use `DB_PATH = Path(tempfile.mkdtemp(prefix="vulnapp-")) / "app.db"` (the
  folder is mode 0700 and unique). This applies to both builds, because the bug is incidental, not planted.

### Integration tests
- `tests/integration/test_against_vulnapp.py`. On the safe build, overwriting another user's note
  fails, and `/ui/notes` without a session does not list other tenants.
- Re-run `heimdall eval vulnapp`: it should still show 7/7 TP, 0 FP and 0 safe-FP.

## Phase 6 — Verify and close out

1. **Unfollowed leads.** No follow-up researcher looked at these three; review each by hand:
   - `src/heimdall/engine.py:75`: the `load_spec` call, mostly covered by F7.
   - `src/heimdall/sast/__init__.py:67`: `result["path"]` and route strings from Semgrep become
     `request_url` and `path_template`. Make sure Phase 3 escaping covers them, and consider
     normalising the path relative to `src_dir`.
   - `vulnapp/app.py:241`: registration. Check the mass-assignment and admin flag handling in the safe build.
2. **Docs.** Bring `docs/threat-model.md` and README in line with the new behaviour: spec fetch
   inside scope, replay scope rules, the redaction list, and loopback-only benchmark ports.
3. **Gates.** Run `pytest`, `heimdall eval vulnapp`, `heimdall eval vampi` and the crAPI suite.
   All must stay at P/R 1.00 and 0 safe-FP.
4. **Rescan.** On a clean tree, run `/claude-security` again with the same scope (everything except
   `crAPI-main/`) to confirm the findings are gone, and to get suggested patches for anything left.

## Suggested commit sequence

1. `scope: require all resolved addresses private; match host:port` (F17 step 1, F18 scope part)
2. `crawler: fetch spec through HttpClient; reject non-rooted spec paths` (F7, F18)
3. `replay: scope from --target/--scope only; method allowlist; strip hop headers` (F12)
4. `evidence: redact identity headers and secret values; strip URL userinfo` (F8, F13)
5. `report: escape untrusted text for terminal and Markdown` (Phase 3)
6. `sast: run semgrep by resolved absolute path` (F14)
7. `vulnapp: harden safe build (note overwrite, ui/notes); private DB dir` (F6, F11, F22)
8. `benchmarks: bind targets to loopback` (F9)
9. `scope: pin vetted IPs per host` (F17 step 2)
10. `docs: update threat model and README`
