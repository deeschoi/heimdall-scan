# Training log

This project is only credible if the checks encode techniques the author
actually understands. This file tracks the labs completed and which check /
test each one produced. A lab is "done" when it is a check plus a test, not
when the box is green.

## PortSwigger Web Security Academy (Practitioner, free)

| Lab track | Status | Encoded into |
|---|---|---|
| Access control / IDOR | ☐ | `checks/bola.py`, `tests/test_bola.py` |
| SSRF (basic + filter bypass + open redirect) | ☐ | `checks/ssrf.py`, `benchmarks/payloads/ssrf.txt` |
| JWT (alg=none, weak secret) | ☐ | `checks/jwt.py`, `tests/test_jwt.py` |
| SQL injection (UNION / error-based) | ☐ | `checks/sqli.py`, `benchmarks/payloads/sqli.txt` |

Do each lab, then reproduce the *technique* as a test against the local labs or
an httpx mock — never against PortSwigger's session-bound instances.

## OWASP WSTG mapping

Every check carries a `wstg` id so findings trace back to a test procedure:

| Check | WSTG |
|---|---|
| bola | [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) |
| ssrf | [WSTG-INPV-19](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery) |
| sqli | WSTG-INPV-05 |
| jwt | WSTG-SESS-10 |
| exposure | WSTG-ATHZ-04 |
| mass_assignment | WSTG-BUSL-08 |

## Payload sources (consumed, not vendored)

- [SecLists](https://github.com/danielmiessler/SecLists) — a curated handful lives in `benchmarks/payloads/`.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — each SSRF/SQLi bypass becomes a unit test, not a dump.
- [HackTricks](https://book.hacktricks.wiki/) — the bypass checklist each check must cover.

## Continuity with prior work

- Sphinx SSRF hardening (redirects, link-local metadata, DNS) → the vectors in
  `benchmarks/payloads/ssrf.txt` and the SSRF oracle. Same cases, opposite role.
