# Heimdall scan report

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

```http
GET http://127.0.0.1:8000/api/me
```

Response: `HTTP 200`

```
{"username":"oed_user_a","tenant":"acme","admin":false}
```
</details>

## HIGH — Error-based SQL injection

- **Check:** `sqli` (`d1461dd77a48`)
- **Endpoint:** `GET /api/products/search`
- **CWE:** CWE-89 · **OWASP API:** API8:2023 · **WSTG:** WSTG-INPV-05 · **ASVS:** 5.3.4
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

A database error was returned when injecting SQL metacharacters, indicating unsanitized input is concatenated into a query.

**Remediation:** Use parameterized queries / an ORM binding; never string-format SQL.

<details><summary>Evidence #1: SQL error signature: 'sqlite3.OperationalError' (payload="'")</summary>

```http
GET http://127.0.0.1:8000/api/products/search?q=%27
```

Response: `HTTP 500`

```
{"error":"sqlite3.OperationalError: unrecognized token: \"'\""}
```
</details>

## HIGH — Excessive data exposure of sensitive fields

- **Check:** `exposure` (`0b6f2160cee7`)
- **Endpoint:** `GET /api/debug/users`
- **CWE:** CWE-200 · **OWASP API:** API3:2023 · **WSTG:** WSTG-ATHZ-04 · **ASVS:** 8.3.4
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

The endpoint returns object fields that should never be serialized to clients: ['password', 'token'].

**Remediation:** Return an explicit response schema; strip secrets server-side.

<details><summary>Evidence #1: Response exposes sensitive field(s): ['password', 'token']</summary>

```http
GET http://127.0.0.1:8000/api/debug/users
```

Response: `HTTP 200`

```
{"users":[{"username":"alice","password":"alice-pw-9f2","email":"alice@acme.example","tenant":"acme","admin":true,"token":"tok_alice_7c1"},{"username":"bob","password":"bob-pw-3a8","email":"bob@acme.example","tenant":"acme","admin":false,"token":"tok_bob_4d2"},{"username":"carol","password":"carol-pw-5e0","email":"carol@globex.example","tenant":"globex","admin":false,"token":"tok_carol_9b7"},{"username":"oed_user_a","password":"pw_a_123","email":"a@acme.example","tenant":"acme","admin":false,"token":"tok_8c4d6f23"},{"username":"oed_user_b","password":"pw_b_123","email":"b@acme.example","tenant
```
</details>

## HIGH — Mass assignment enables privilege escalation

- **Check:** `mass_assignment` (`e53b0abcab5c`)
- **Endpoint:** `POST /api/register`
- **CWE:** CWE-915 · **OWASP API:** API6:2023 · **WSTG:** WSTG-BUSL-08 · **ASVS:** 5.1.2
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

A create endpoint honored a privileged attribute supplied by the client, allowing self-granted elevated privileges.

**Remediation:** Bind requests to an explicit input schema; never mass-assign models.

<details><summary>Evidence #1: Created principal '459bc918f2' shows admin=True</summary>

```http
GET http://127.0.0.1:8000/api/debug/users
```

Response: `HTTP 200`

```
{"users":[{"username":"alice","password":"alice-pw-9f2","email":"alice@acme.example","tenant":"acme","admin":true,"token":"tok_alice_7c1"},{"username":"bob","password":"bob-pw-3a8","email":"bob@acme.example","tenant":"acme","admin":false,"token":"tok_bob_4d2"},{"username":"carol","password":"carol-pw-5e0","email":"carol@globex.example","tenant":"globex","admin":false,"token":"tok_carol_9b7"},{"username":"oed_user_a","password":"pw_a_123","email":"a@acme.example","tenant":"acme","admin":false,"token":"tok_8c4d6f23"},{"username":"oed_user_b","password":"pw_b_123","email":"b@acme.example","tenant
```
</details>

<details><summary>Evidence #2: Injected privileged field via create: {'admin': True}</summary>

```http
POST http://127.0.0.1:8000/api/register

{"username":"459bc918f2","password":"pw123","email":"ma@acme.example","admin":true}
```

Response: `HTTP 200`

```
{"username":"459bc918f2","email":"ma@acme.example","admin":true}
```
</details>

## HIGH — Broken object level authorization (IDOR)

- **Check:** `bola` (`70ebdcb9f647`)
- **Endpoint:** `GET /api/notes/{note_id}`
- **CWE:** CWE-639 · **OWASP API:** API1:2023 · **WSTG:** WSTG-ATHZ-04 · **ASVS:** 4.2.1
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

An object owned by one principal was readable by another; the server performs no object-level ownership check.

**Remediation:** Enforce per-object ownership checks on every read/write path.

<details><summary>Evidence #1: Cross-tenant canary 'HEIMDALL_CANARY_ab12c' leaked to identity 'user_b'</summary>

```http
GET http://127.0.0.1:8000/api/notes/heimdall_bola_note
```

Response: `HTTP 200`

```
{"id":"heimdall_bola_note","title":"q3-plan","body":"internal","secret":"HEIMDALL_CANARY_ab12c","owner":"oed_user_a","tenant":"acme"}
```
</details>

## HIGH — JWT signed with a weak, guessable secret

- **Check:** `jwt` (`10d043a768b7`)
- **Endpoint:** `POST (login)`
- **CWE:** CWE-347 · **OWASP API:** API2:2023 · **WSTG:** WSTG-SESS-10 · **ASVS:** 3.5.3
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

The HMAC secret is guessable, so any token can be forged.

**Remediation:** Use a long random secret from a secrets manager; rotate it.

<details><summary>Evidence #1: Token signature verifies with guessable secret 'changeme'</summary>

```http
- http://127.0.0.1:8000
```

Response: `HTTP None`

```

```
</details>

## HIGH — Server-side request forgery

- **Check:** `ssrf` (`4b7a63f34a1d`)
- **Endpoint:** `POST /api/url-preview`
- **CWE:** CWE-918 · **OWASP API:** API7:2023 · **WSTG:** WSTG-INPV-19 · **ASVS:** 12.6.1
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`

A URL parameter caused the server to fetch an attacker-controlled internal resource.

**Remediation:** Validate against an egress allowlist; block link-local/RFC1918; disable redirects.

<details><summary>Evidence #1: Injected canary reflected in response: 'ami-id'</summary>

```http
POST http://127.0.0.1:8000/api/url-preview

{"url":"http://127.0.0.1:8000/internal/latest/meta-data/"}
```

Response: `HTTP 200`

```
{"url":"http://127.0.0.1:8000/internal/latest/meta-data/","status":200,"body":"ami-id\nami-launch-index\nhostname\niam/security-credentials/\ninstance-id\ninstance-type\nlocal-ipv4\n"}
```
</details>

