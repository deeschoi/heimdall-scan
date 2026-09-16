# Check: `bola` — Broken Object Level Authorization (IDOR)

- **CWE:** CWE-639 · **OWASP API:** API1:2023 · **WSTG:** WSTG-ATHZ-04 · **ASVS:** 4.2.1

## Oracle
Identity A owns an object carrying a unique **canary** value. Identity B
requests that same object. If A's canary appears in B's response, B read data it
never had access to — a proven authorization break (no heuristics).

## Coverage checklist
- [x] Two distinct authenticated identities.
- [x] Owner-created object with a random canary (no reliance on seed data).
- [x] Cross-tenant read via the object-id endpoint.
- [ ] Sequential-integer id enumeration (crAPI mechanic reports).
- [ ] UUID id enumeration via a list endpoint.
- [x] Replayable: `heimdall replay` re-issues B's read and re-checks the canary.

## Config (suite `hints.bola`)
```yaml
bola:
  - create: { path: /books/v1, method: POST, as: user_a,
              json: { book_title: heimdall_bola_book, secret: "HEIMDALL_CANARY_9f21a" } }
    read:   { path: /books/v1/heimdall_bola_book, method: GET, as: user_b,
              path_template: "/books/v1/{book_title}" }
    canary: "HEIMDALL_CANARY_9f21a"
```
