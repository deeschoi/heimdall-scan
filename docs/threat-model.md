# Threat model (one-pager)

Scope: **Oedipus is an active DAST tool.** The threat model here is about the
*scanner*, not the deliberately-vulnerable targets it scans.

## Assets
- The operator's authorization to scan a target (legal exposure if misused).
- Target availability (a scanner that hammers a host is a DoS).
- Any credentials/tokens the scanner is handed to authenticate as a user.

## Trust boundaries
- Operator → Oedipus: CLI flags and suite YAML (trusted input).
- Oedipus → target: every outbound request (must stay in scope).
- Target → Oedipus: responses (untrusted; parsed defensively).

## Abuse cases and mitigations
| Abuse case | Mitigation in code |
|---|---|
| Scan a host you don't own | `scope.py`: allowlist; only private/loopback by default; public needs `--i-understand`. |
| Destroy target data | `http_client.py`: `PUT/DELETE/PATCH` blocked unless `--unsafe`. |
| Accidental DoS | Rate limiter (`--rate-limit`, default 20 rps). |
| Leak the operator's token into a report | Reports embed request headers; keep reports out of VCS (`.gitignore`). |
| SSRF payloads escaping the lab | SSRF canaries target link-local/loopback; scope guard still applies to the scanner's own requests. |

## Non-goals
- No auto-exploitation beyond what proves a finding.
- No LLM "oracle": exploration may be heuristic/LLM-assisted, but every finding
  is a deterministic, replayable check.
- No scanning of the public internet as a demo (CI stays on localhost compose).
