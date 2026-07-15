# Planted vulnerabilities

28 distinct, **exploitable** vulnerabilities (36 tagged sink locations) across
Java (Spring Boot), JavaScript (browser), and SQL. Every sink is marked in the
source with a `VULN:VULN-xx:CWE-nnn` comment so the ground-truth `reference.sarif`
can be generated straight from the code (`checker/build_reference.py`).

| ID | CWE | Class | Location(s) | Exploitable via |
|----|-----|-------|-------------|-----------------|
| VULN-01 | CWE-89 | SQL Injection | `SearchController.java:36`, `ProfileController.java:34,60` | `GET /search?q=`, `GET /profile?id=`, `POST /profile/update` |
| VULN-02 | CWE-89 | SQL Injection (auth bypass) | `AuthController.java:42` | `POST /login` |
| VULN-03 | CWE-79 | Reflected XSS | `SearchController.java:50`, `search.html:14` | `GET /search?q=` |
| VULN-04 | CWE-79 | Stored XSS | `ProfileController.java:41`, `profile.html:17` | `POST /profile/update` → `GET /profile` |
| VULN-05 | CWE-78 | OS Command Injection | `AdminController.java:28` | `GET /admin/ping?host=` |
| VULN-06 | CWE-22 | Path Traversal | `FileController.java:27` | `GET /files/download?name=` |
| VULN-07 | CWE-434 | Unrestricted File Upload | `FileController.java:42` | `POST /files/upload` |
| VULN-08 | CWE-502 | Insecure Deserialization | `ApiController.java:32` | `POST /api/deserialize` |
| VULN-09 | CWE-611 | XXE | `ApiController.java:49` | `POST /api/xml` |
| VULN-10 | CWE-918 | SSRF | `AdminController.java:47` | `GET /admin/fetch?url=` |
| VULN-11 | CWE-200 | Sensitive Data Exposure (SSN) | `ProfileController.java:43`, `profile.html:15` | `GET /profile?id=` |
| VULN-12 | CWE-639 | IDOR / Broken Access Control | `ProfileController.java:33` | `GET /profile?id=` |
| VULN-13 | CWE-327 | Weak Hash (MD5) | `CryptoUtil.java:26` | password hashing |
| VULN-14 | CWE-798 | Hard-coded Secret/Credentials | `CryptoUtil.java:16` | source review |
| VULN-15 | CWE-306 | Missing Auth for Critical Function | `AdminController.java:26` | `GET /admin/*` (no auth) |
| VULN-16 | CWE-209 | Verbose Error / Info Leak | `AuthController.java:67`, `SearchController.java:47` | `POST /login`, `GET /search` |
| VULN-17 | CWE-614 | Insecure Cookie (no HttpOnly/Secure) | `AuthController.java:54` | `POST /login` response cookie |
| VULN-18 | CWE-330 | Insufficiently Random Token | `AuthController.java:52`, `CryptoUtil.java:37` | session/reset token |
| VULN-19 | CWE-256 | Unsalted Password Storage | `db/init.sql:10` | schema/data |
| VULN-20 | CWE-312 | Cleartext Sensitive Storage | `db/init.sql:12` | schema/data |
| VULN-21 | CWE-732 | Excessive DB Privileges | `db/init.sql:40` | `GRANT ALL` |
| VULN-22 | CWE-329 | Static IV with CBC | `CryptoUtil.java:19` | source review |
| VULN-23 | CWE-327 | Hard-coded AES Key / weak crypto | `CryptoUtil.java:48` | source review |
| VULN-24 | CWE-601 | Open Redirect | `ApiController.java:66` | `GET /api/redirect?url=` |
| VULN-25 | CWE-470 | Unsafe Reflection | `ApiController.java:79` | `GET /api/plugin?class=` |
| VULN-26 | CWE-79 | DOM-based XSS | `static/js/app.js:12,18` | `/welcome.html#...`, `?q=` |
| VULN-27 | CWE-798 | Hard-coded API Key in JS | `static/js/app.js:3` | browser source |
| VULN-28 | CWE-95 | Client-side `eval()` Code Injection | `static/js/app.js:22` | `/welcome.html?calc=` |

## Language coverage

- **Java / Spring Boot** — VULN-01…18, 22, 23, 24, 25 (server-side sinks)
- **SQL** — VULN-19, 20, 21 (insecure schema, storage, privileges)
- **JavaScript (browser)** — VULN-26, 27, 28 (DOM XSS, secret leakage, eval)

## Ground truth

`checker/reference.sarif` is generated from the markers above by
`checker/build_reference.py`. It contains **36 results** (one per sink location).
A SAST tool is scored against it with `checker/sast_checker.py` — see the top-level
`README.md`.

See `docs/exploitation-guide.md` for copy-paste exploitation of every item and
`poc/exploit_all.py` for an automated end-to-end proof that they fire.
