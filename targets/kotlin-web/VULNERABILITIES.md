# Planted vulnerabilities — kotlin-web target

31 distinct, **exploitable** vulnerabilities (Kotlin + Spring Boot + H2).
One file = one primary sink (1:1); each a real wired endpoint. Markers
`VULN:VULN-xx:CWE-nnn:class` drive the reference SARIF.

Detection classes: taint=15, pattern=4, config=5, logic=7.
Headline metric = engine (taint) recall. See `docs/benchmark-methodology.md`.

| ID | CWE | Class | Title | Endpoint | Sink |
|----|-----|-------|-------|----------|------|
| VULN-01 | CWE-89 | taint | SQL Injection (search) | `GET /vuln01/search?q=` | `vulns/Vuln01SqlSearch.kt:14` |
| VULN-02 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln02/login` | `vulns/Vuln02SqlLogin.kt:14` |
| VULN-03 | CWE-79 | taint | Reflected XSS | `GET /vuln03/echo?q=` | `vulns/Vuln03ReflectedXss.kt:11` |
| VULN-04 | CWE-79 | taint | Stored XSS | `POST /vuln04/save -> /vuln04/show` | `vulns/Vuln04StoredXss.kt:14` |
| VULN-05 | CWE-78 | taint | OS Command Injection | `GET /vuln05/ping?host=` | `vulns/Vuln05CmdInjection.kt:11` |
| VULN-06 | CWE-22 | taint | Path Traversal | `GET /vuln06/download?name=` | `vulns/Vuln06PathTraversal.kt:11` |
| VULN-08 | CWE-502 | taint | Insecure Deserialization | `POST /vuln08/deserialize` | `vulns/Vuln08Deserialize.kt:12` |
| VULN-09 | CWE-611 | taint | XXE | `POST /vuln09/xml` | `vulns/Vuln09Xxe.kt:12` |
| VULN-10 | CWE-918 | taint | SSRF | `GET /vuln10/fetch?url=` | `vulns/Vuln10Ssrf.kt:11` |
| VULN-11 | CWE-200 | logic | Sensitive Data Exposure (SSN) | `GET /vuln11/profile?id=` | `vulns/Vuln11SsnExposure.kt:14` |
| VULN-12 | CWE-639 | logic | IDOR | `GET /vuln12/account?id=` | `vulns/Vuln12Idor.kt:12` |
| VULN-13 | CWE-327 | pattern | Weak Hash (MD5) | `GET /vuln13/hash?p=` | `crypto/Crypto.kt:13` |
| VULN-16 | CWE-209 | logic | Verbose Error | `GET /vuln16/lookup?id=` | `vulns/Vuln16VerboseError.kt:15` |
| VULN-17 | CWE-614 | config | Insecure Cookie | `POST /vuln17/login` | `vulns/Vuln17InsecureCookie.kt:12` |
| VULN-18 | CWE-330 | pattern | Predictable Token | `GET /vuln18/token?user=` | `crypto/Crypto.kt:34` |
| VULN-19 | CWE-256 | config | Unsalted Password Storage | `seed schema` | `vulnapp/VulnApp.kt:18` |
| VULN-20 | CWE-312 | config | Cleartext Storage | `seed schema` | `vulnapp/VulnApp.kt:19` |
| VULN-22 | CWE-329 | pattern | Static IV | `GET /vuln22/encrypt?data=` | `crypto/Crypto.kt:22` |
| VULN-23 | CWE-321 | pattern | Hard-coded AES Key | `GET /vuln22/encrypt?data=` | `crypto/Crypto.kt:20` |
| VULN-24 | CWE-601 | taint | Open Redirect | `GET /vuln24/redirect?url=` | `vulns/Vuln24OpenRedirect.kt:11` |
| VULN-25 | CWE-470 | taint | Unsafe Reflection | `GET /vuln25/plugin?class=` | `vulns/Vuln25UnsafeReflection.kt:11` |
| VULN-29 | CWE-915 | logic | Mass Assignment | `POST /vuln29/register` | `vulns/Vuln29MassAssignment.kt:15` |
| VULN-32 | CWE-917 | taint | SpEL Injection | `GET /vuln32/eval?expr=` | `vulns/Vuln32Spel.kt:11` |
| VULN-33 | CWE-1236 | taint | CSV Injection | `GET /vuln33/export?note=` | `vulns/Vuln33CsvInjection.kt:11` |
| VULN-34 | CWE-942 | config | Insecure CORS | `GET /vuln34/data (Origin)` | `vulns/Vuln34Cors.kt:13` |
| VULN-35 | CWE-1021 | config | Clickjacking | `application.properties` | `resources/application.properties:17` |
| VULN-36 | CWE-190 | logic | Integer Overflow | `GET /vuln36/order?price=&qty=` | `vulns/Vuln36IntOverflow.kt:11` |
| VULN-37 | CWE-643 | taint | XPath Injection | `GET /vuln37/xlookup?user=` | `vulns/Vuln37Xpath.kt:13` |
| VULN-38 | CWE-1333 | logic | ReDoS | `GET /vuln38/validate?email=` | `vulns/Vuln38Redos.kt:12` |
| VULN-39 | CWE-117 | taint | Log Injection | `GET /vuln39/note?text=` | `vulns/Vuln39LogInjection.kt:11` |
| VULN-40 | CWE-384 | logic | Session Fixation | `GET /vuln40/setsession?sid=` | `vulns/Vuln40SessionFixation.kt:11` |
