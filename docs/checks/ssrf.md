# Check: `ssrf` — Server-Side Request Forgery

- **CWE:** CWE-918 · **OWASP API:** API7:2023 · **WSTG:** WSTG-INPV-19 · **ASVS:** 12.6.1

## Oracle
Point a URL-valued parameter at an internal canary and confirm the server
actually fetched it — either a reflected marker in the response or a
metadata-service fingerprint (`ami-id`, `iam/security-credentials`,
`computeMetadata`). No blind timing guesses, so apps without a fetch sink
produce **no** finding (no false positives).

## Coverage checklist (from PayloadsAllTheThings / HackTricks)
- [x] Loopback: `http://127.0.0.1/`, `http://127.1/`, `http://localhost/`
- [x] Decimal / hex IP: `http://2130706433/`, `http://0x7f000001/`
- [x] IPv6 loopback + mapped: `http://[::1]/`, `[0:0:0:0:0:ffff:127.0.0.1]`
- [x] Cloud metadata: AWS `169.254.169.254`, GCP `metadata.google.internal`
- [ ] Redirect-to-metadata (open redirect chained into SSRF)
- [ ] DNS rebinding

Payloads live in `benchmarks/payloads/ssrf.txt`.

## Config (suite `hints.ssrf`)
```yaml
ssrf:
  - path: /workshop/api/merchant/contact_mechanic
    method: POST
    param: mechanic_api
    location: body
    canary: "http://169.254.169.254/latest/meta-data/"
    match: "ami-id"
```
