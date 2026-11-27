# Threat model (one-pager)

Scope: **Heimdall is an active DAST tool.** The threat model here is about the
*scanner*, not the deliberately-vulnerable targets it scans.

## Assets
- The operator's authorization to scan a target (legal exposure if misused).
- Target availability (a scanner that hammers a host is a DoS).
- Any credentials/tokens the scanner is handed to authenticate as a user.

## Trust boundaries
- Operator → Heimdall: CLI flags and suite YAML (trusted input).
- Heimdall → target: every outbound request, including login and the OpenAPI spec fetch, goes through `HttpClient` and must stay in scope.
- Target → Heimdall: responses and the target's OpenAPI spec (untrusted; parsed defensively, never trusted to choose hosts, ports, or terminal output).
- Report files → Heimdall: `replay`, `gate`, `correlate` and `explain` read JSON reports, which are shared and uploaded as artifacts (untrusted data, not configuration).
- Scanned source → Heimdall: `heimdall sast` reads a source tree that may be untrusted (route strings and file names are data).

## Abuse cases and mitigations
| Abuse case | Mitigation in code |
|---|---|
| Scan a host you don't own | `scope.py`: allowlist is `host:port` of the named target plus `--scope` entries (a bare `--scope host` allows every port on it). A hostname counts as private only if every address it resolves to is private; a public host requires `--i-understand` (`Scope.validate`). Vetted addresses are pinned, so DNS rebinding cannot move traffic to a public IP. Redirect hops are scope-checked too. |
| Hostile spec steers probes | `crawler/openapi.py` drops spec paths that are not rooted (`/...`) or carry control characters; `ScanContext.url` refuses any join that leaves the base URL's scheme, host and port. |
| Crafted report steers `replay` | Scope comes only from `--target`/`--scope`, never from the report. Stored `Host` and hop-by-hop headers are dropped; POST needs `--allow-post`. |
| Destroy target data | `http_client.py`: only `GET/HEAD/OPTIONS/POST` are sent without `--unsafe` (blocks `PUT/PATCH/DELETE` and non-standard verbs), including `replay` and suite hints. |
| Accidental DoS | Rate limiter (`--rate-limit`, default 20 rps), applied to login as well. |
| Leak the operator's token into a report | Evidence drops every header an identity injects, the fixed credential headers (`Authorization`, `Cookie`, `X-Api-Key`, ...) and any header whose name looks like a credential; it masks identity token values wherever they appear. `user:pass@` in a target URL becomes Basic auth for that host and is stripped from URLs in findings, evidence and the report target. Keep reports out of VCS (`.gitignore`). |
| TLS interception of the scanner | Certificates are verified unless `--insecure`, for the OpenAPI spec fetch as well. |
| Target or report drives the operator's terminal | `report/safe_text.py`: control characters (ANSI/OSC escapes, C1, bidi overrides) are shown escaped in the transcript and printed reports; Rich markup is off for report text. |
| Target restructures the Markdown report | Evidence goes in code fences longer than any backtick run in it; inline fields are code spans or HTML-escaped text, and table cells escape `\|`. |
| Planted `semgrep` in the scanned tree | `sast/runner.py` runs semgrep by absolute path from absolute `PATH` entries only (or `HEIMDALL_SEMGREP`); the current folder is never searched. |
| Lab targets exposed to the network | `benchmarks/compose.yml` publishes every vulnerable target on `127.0.0.1` only. |
| SSRF payloads escaping the lab | SSRF canaries target link-local/loopback; scope guard still applies to the scanner's own requests. |

## Non-goals
- No auto-exploitation beyond what proves a finding.
- No LLM "oracle": exploration may be heuristic/LLM-assisted, but every finding
  is a deterministic, replayable check.
- No scanning of the public internet as a demo (CI stays on localhost compose).
