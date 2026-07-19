# Planted vulnerabilities — java-web target

40 distinct, **exploitable** vulnerabilities. One file = one primary sink (1:1),
each a real wired endpoint. Every sink is marked `VULN:VULN-xx:CWE-nnn:class`;
the reference SARIF is generated from those markers.

Detection class drives scoring: **taint** = the SAST engine must trace source→sink
(headline metric); **pattern** = signature/bad-API; **config** = schema/settings;
**logic** = business-logic (usually expected static FN). See `docs/benchmark-methodology.md`.

| ID | CWE | Class | Title | Endpoint | Sink location |
|----|-----|-------|-------|----------|---------------|
| VULN-01 | CWE-89 | taint | SQL Injection (search) | `GET /vuln01/search?q=` | `vulns/Vuln01SqlSearch.java:17` |
| VULN-02 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln02/login` | `vulns/Vuln02SqlLogin.java:19` |
| VULN-03 | CWE-79 | taint | Reflected XSS | `GET /vuln03/echo?q=` | `vulns/Vuln03ReflectedXss.java:10` |
| VULN-04 | CWE-79 | taint | Stored XSS | `POST /vuln04/save -> GET /vuln04/show` | `vulns/Vuln04StoredXss.java:21` |
| VULN-05 | CWE-78 | taint | OS Command Injection | `GET /vuln05/ping?host=` | `vulns/Vuln05CmdInjection.java:12` |
| VULN-06 | CWE-22 | taint | Path Traversal | `GET /vuln06/download?name=` | `vulns/Vuln06PathTraversal.java:14` |
| VULN-07 | CWE-434 | taint | Unrestricted File Upload | `POST /vuln07/upload` | `vulns/Vuln07FileUpload.java:14` |
| VULN-08 | CWE-502 | taint | Insecure Deserialization | `POST /vuln08/deserialize` | `vulns/Vuln08Deserialize.java:13` |
| VULN-09 | CWE-611 | taint | XXE | `POST /vuln09/xml` | `vulns/Vuln09Xxe.java:14` |
| VULN-10 | CWE-918 | taint | SSRF | `GET /vuln10/fetch?url=` | `vulns/Vuln10Ssrf.java:13` |
| VULN-11 | CWE-200 | logic | Sensitive Data Exposure (SSN) | `GET /vuln11/profile?id=` | `vulns/Vuln11SsnExposure.java:21` |
| VULN-12 | CWE-639 | logic | IDOR / Broken Access Control | `GET /vuln12/account?id=` | `vulns/Vuln12Idor.java:16` |
| VULN-13 | CWE-327 | pattern | Weak Hash (MD5) | `GET /vuln13/hash?p=` | `crypto/WeakHash.java:13` |
| VULN-14 | CWE-798 | pattern | Hard-coded Admin Token | `GET /vuln14/admin?token=` | `crypto/Secrets.java:7` |
| VULN-15 | CWE-306 | logic | Missing Auth (critical fn) | `GET /vuln15/shutdown` | `vulns/Vuln15MissingAuth.java:9` |
| VULN-16 | CWE-209 | logic | Verbose Error / Info Leak | `GET /vuln16/lookup?id=` | `vulns/Vuln16VerboseError.java:19` |
| VULN-17 | CWE-614 | config | Insecure Cookie (no flags) | `POST /vuln17/login` | `vulns/Vuln17InsecureCookie.java:14` |
| VULN-18 | CWE-330 | pattern | Predictable Session Token | `GET /vuln18/token?user=` | `crypto/Secrets.java:14` |
| VULN-19 | CWE-256 | config | Unsalted Password Storage | `db/init.sql` | `db/init.sql:10` |
| VULN-20 | CWE-312 | config | Cleartext Sensitive Storage | `db/init.sql` | `db/init.sql:12` |
| VULN-21 | CWE-732 | config | Excessive DB Privileges | `db/init.sql (GRANT ALL)` | `db/init.sql:40` |
| VULN-22 | CWE-329 | pattern | Static IV (CBC) | `GET /vuln22/encrypt?data=` | `crypto/AesCipher.java:12` |
| VULN-23 | CWE-321 | pattern | Hard-coded AES Key | `GET /vuln22/encrypt?data=` | `crypto/AesCipher.java:10` |
| VULN-24 | CWE-601 | taint | Open Redirect | `GET /vuln24/redirect?url=` | `vulns/Vuln24OpenRedirect.java:11` |
| VULN-25 | CWE-470 | taint | Unsafe Reflection | `GET /vuln25/plugin?class=` | `vulns/Vuln25UnsafeReflection.java:10` |
| VULN-26 | CWE-79 | taint | DOM-based XSS | `/welcome.html#name=` | `js/app.js:14` |
| VULN-27 | CWE-798 | pattern | Hard-coded API Key (JS) | `GET /js/app.js` | `js/app.js:4` |
| VULN-28 | CWE-95 | taint | Client-side eval() | `/welcome.html?calc=` | `js/app.js:17` |
| VULN-29 | CWE-915 | logic | Mass Assignment (role) | `POST /vuln29/register` | `vulns/Vuln29MassAssignment.java:18` |
| VULN-30 | CWE-307 | logic | No Rate Limiting | `POST /vuln30/login (xN)` | `vulns/Vuln30NoRateLimit.java:14` |
| VULN-31 | CWE-347 | logic | JWT Signature Not Verified | `GET /vuln31/whoami` | `vulns/Vuln31JwtNone.java:16` |
| VULN-32 | CWE-917 | taint | EL / SpEL Injection | `GET /vuln32/eval?expr=` | `vulns/Vuln32Spel.java:11` |
| VULN-33 | CWE-1236 | taint | CSV / Formula Injection | `GET /vuln33/export?note=` | `vulns/Vuln33CsvInjection.java:9` |
| VULN-34 | CWE-942 | config | Insecure CORS | `GET /vuln34/data (Origin)` | `vulns/Vuln34Cors.java:11` |
| VULN-35 | CWE-1021 | config | Clickjacking (no XFO) | `application.properties` | `resources/application.properties:18` |
| VULN-36 | CWE-190 | logic | Integer Overflow (order) | `GET /vuln36/order?price=&qty=` | `vulns/Vuln36IntOverflow.java:9` |
| VULN-37 | CWE-643 | taint | XPath Injection | `GET /vuln37/xlookup?user=` | `vulns/Vuln37Xpath.java:18` |
| VULN-38 | CWE-1333 | logic | ReDoS (evil regex) | `GET /vuln38/validate?email=` | `vulns/Vuln38Redos.java:8` |
| VULN-39 | CWE-117 | taint | Log Injection | `GET /vuln39/note?text=` | `vulns/Vuln39LogInjection.java:9` |
| VULN-40 | CWE-384 | logic | Session Fixation | `GET /vuln40/setsession?sid=` | `vulns/Vuln40SessionFixation.java:11` |

## By detection class
| class | count | meaning |
|-------|-------|---------|
| taint | 18 | engine dataflow — **headline recall metric** |
| pattern | 6 | signature / bad crypto API |
| config | 6 | schema / settings / headers |
| logic | 10 | business logic — usually expected static FN |

See top-level `README.md` for how to build, exploit, scan and score.
