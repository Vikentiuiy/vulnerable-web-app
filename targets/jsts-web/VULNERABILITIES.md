# Planted vulnerabilities — jsts-web target

25 distinct, **exploitable** vulnerabilities (Node/Express + TypeScript, better-sqlite3).
One file = one primary sink (Router per vuln). Includes JS-specific **prototype pollution** and eval code injection.

Detection classes: taint=12, pattern=2, config=5, logic=6. Headline = engine (taint) recall.

| ID | CWE | Class | Title | Endpoint | Sink |
|----|-----|-------|-------|----------|------|
| VULN-01 | CWE-89 | taint | SQL Injection (search) | `GET /vuln01/search?q=` | `vulns/vuln01_sqli.ts:6` |
| VULN-02 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln02/login` | `vulns/vuln02_sqli_login.ts:8` |
| VULN-03 | CWE-79 | taint | Reflected XSS | `GET /vuln03/echo?q=` | `vulns/vuln03_reflected_xss.ts:5` |
| VULN-04 | CWE-79 | taint | Stored XSS | `POST /vuln04/save -> /vuln04/show` | `vulns/vuln04_stored_xss.ts:7` |
| VULN-05 | CWE-78 | taint | OS Command Injection | `GET /vuln05/ping?host=` | `vulns/vuln05_cmd.ts:6` |
| VULN-06 | CWE-22 | taint | Path Traversal | `GET /vuln06/download?name=` | `vulns/vuln06_path.ts:6` |
| VULN-10 | CWE-918 | taint | SSRF | `GET /vuln10/fetch?url=` | `vulns/vuln10_ssrf.ts:6` |
| VULN-11 | CWE-200 | logic | Sensitive Data Exposure (SSN) | `GET /vuln11/profile?id=` | `vulns/vuln11_ssn.ts:6` |
| VULN-12 | CWE-639 | logic | IDOR | `GET /vuln12/account?id=` | `vulns/vuln12_idor.ts:5` |
| VULN-13 | CWE-327 | pattern | Weak Hash (MD5) | `GET /vuln13/hash?p=` | `vulns/vuln13_hash.ts:5` |
| VULN-16 | CWE-209 | logic | Verbose Error | `GET /vuln16/lookup?id=` | `vulns/vuln16_verbose.ts:7` |
| VULN-17 | CWE-614 | config | Insecure Cookie | `GET /vuln17/login?user=` | `vulns/vuln17_cookie.ts:5` |
| VULN-18 | CWE-330 | pattern | Predictable Token (Math.random) | `GET /vuln18/token?user=` | `vulns/vuln18_token.ts:4` |
| VULN-19 | CWE-256 | config | Unsalted Password Storage | `seed schema` | `src/store.ts:6` |
| VULN-20 | CWE-312 | config | Cleartext Storage | `seed schema` | `src/store.ts:7` |
| VULN-24 | CWE-601 | taint | Open Redirect | `GET /vuln24/redirect?url=` | `vulns/vuln24_redirect.ts:4` |
| VULN-29 | CWE-915 | logic | Mass Assignment | `POST /vuln29/register` | `vulns/vuln29_mass_assign.ts:8` |
| VULN-32 | CWE-95 | taint | Code Injection (eval) | `GET /vuln32/calc?expr=` | `vulns/vuln32_eval.ts:5` |
| VULN-33 | CWE-1236 | taint | CSV Injection | `GET /vuln33/export?note=` | `vulns/vuln33_csv.ts:5` |
| VULN-34 | CWE-942 | config | Insecure CORS | `GET /vuln34/data (Origin)` | `vulns/vuln34_cors.ts:6` |
| VULN-35 | CWE-1021 | config | Clickjacking | `any response` | `src/app.ts:27` |
| VULN-38 | CWE-1333 | logic | ReDoS | `GET /vuln38/validate?email=` | `vulns/vuln38_redos.ts:3` |
| VULN-39 | CWE-117 | taint | Log Injection | `GET /vuln39/note?text=` | `vulns/vuln39_log.ts:5` |
| VULN-40 | CWE-384 | logic | Session Fixation | `GET /vuln40/setsession?sid=` | `vulns/vuln40_session.ts:5` |
| VULN-43 | CWE-1321 | taint | Prototype Pollution | `POST /vuln43/merge` | `vulns/vuln43_proto_pollution.ts:12` |
