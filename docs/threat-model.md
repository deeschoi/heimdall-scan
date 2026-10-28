# Threat model (one-pager)

Scope: **Heimdall is an active DAST tool.** The threat model here is about the
*scanner*, not the deliberately-vulnerable targets it scans.

## Assets
- The operator's authorization to scan a target (legal exposure if misused).
- Target availability (a scanner that hammers a host is a DoS).
- Any credentials/tokens the scanner is handed to authenticate as a user.

## Trust boundaries
- Operator → Heimdall: CLI flags and suite YAML (trusted input).
- Heimdall → target: every outbound request, including login, goes through `HttpClient` and must stay in scope.
- Target → Heimdall: responses (untrusted; parsed defensively).

## Abuse cases and mitigations
| Abuse case | Mitigation in code |
|---|---|
| Scan a host you don't own | `scope.py`: allowlist is the named target plus `--scope` hosts only. A public host requires `--i-understand` (`Scope.validate`). |
| Destroy target data | `http_client.py`: `PUT/DELETE/PATCH` blocked unless `--unsafe`, including `replay` and suite hints. |
| Accidental DoS | Rate limiter (`--rate-limit`, default 20 rps), applied to login as well. |
| Leak the operator's token into a report | Evidence drops credential request headers (`Authorization`, `Cookie`, `X-Api-Key`, and similar) and redacts them in response headers. Keep reports out of VCS (`.gitignore`). |
| TLS interception of the scanner | Certificates are verified unless `--insecure`. |
| SSRF payloads escaping the lab | SSRF canaries target link-local/loopback; scope guard still applies to the scanner's own requests. |

## Non-goals
- No auto-exploitation beyond what proves a finding.
- No LLM "oracle": exploration may be heuristic/LLM-assisted, but every finding
  is a deterministic, replayable check.
- No scanning of the public internet as a demo (CI stays on localhost compose).
