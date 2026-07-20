# Planted vulnerabilities — swift target

20 distinct, **exploitable** vulnerabilities (Swift + Vapor). One file = one sink.

Detection classes: taint=9, pattern=3, config=3, logic=5.

| ID | CWE | Class | Vulnerability | Endpoint | Sink |
|----|-----|-------|---------------|----------|------|
| VULN-03 | CWE-79 | taint | reflected XSS: input echoed into HTML unes | `GET /vuln03/echo?q=` | `Vuln03ReflectedXss.swift:6` |
| VULN-04 | CWE-79 | taint | stored XSS: persisted bio rendered into HT | `GET /vuln04/save -> /vuln04/show` | `Vuln04StoredXss.swift:12` |
| VULN-05 | CWE-78 | taint | OS command injection — host concatenated i | `GET /vuln05/ping?host=` | `Vuln05CmdInjection.swift:9` |
| VULN-06 | CWE-22 | taint | path traversal — user input concatenated i | `GET /vuln06/download?name=` | `Vuln06PathTraversal.swift:7` |
| VULN-10 | CWE-918 | taint | SSRF — server fetches an arbitrary user-su | `GET /vuln10/fetch?url=` | `Vuln10Ssrf.swift:7` |
| VULN-11 | CWE-200 | logic | sensitive data (SSN) returned to any calle | `GET /vuln11/profile?id=` | `Vuln11SsnExposure.swift:5` |
| VULN-13 | CWE-327 | pattern | broken/weak hash (MD5) used for passwords | `GET /vuln13/hash?p=` | `Vuln13Hash.swift:8` |
| VULN-16 | CWE-209 | logic | internal error + query detail returned to  | `GET /vuln16/lookup?id=` | `Vuln16VerboseError.swift:6` |
| VULN-17 | CWE-614 | config | auth cookie set without HttpOnly/Secure fl | `GET /vuln17/login?user=` | `Vuln17InsecureCookie.swift:9` |
| VULN-18 | CWE-330 | pattern | predictable token derived deterministicall | `GET /vuln18/token?user=` | `Vuln18PredictableToken.swift:7` |
| VULN-22 | CWE-329 | pattern | hard-coded key + fixed nonce -> determinis | `GET /vuln22/encrypt?data=` | `Vuln22WeakCrypto.swift:7` |
| VULN-24 | CWE-601 | taint | open redirect — unvalidated redirect targe | `GET /vuln24/redirect?url=` | `Vuln24OpenRedirect.swift:6` |
| VULN-29 | CWE-915 | logic | caller-controlled role bound directly (pri | `GET /vuln29/register?role=` | `Vuln29MassAssignment.swift:6` |
| VULN-33 | CWE-1236 | taint | user data written into CSV without neutral | `GET /vuln33/export?note=` | `Vuln33CsvInjection.swift:6` |
| VULN-34 | CWE-942 | config | arbitrary Origin reflected + credentials a | `GET /vuln34/data (Origin)` | `Vuln34Cors.swift:7` |
| VULN-35 | CWE-1021 | config | no X-Frame-Options / CSP frame-ancestors m | `any response` | `main.swift:7` |
| VULN-38 | CWE-1333 | logic | catastrophically-backtracking regex applie | `GET /vuln38/validate?email=` | `Vuln38Redos.swift:7` |
| VULN-39 | CWE-117 | taint | user input logged without neutralising CR/ | `GET /vuln39/note?text=` | `Vuln39LogInjection.swift:6` |
| VULN-40 | CWE-384 | logic | attacker-supplied session id adopted as-is | `GET /vuln40/setsession?sid=` | `Vuln40SessionFixation.swift:6` |
| VULN-45 | CWE-113 | taint | untrusted input reflected into a response  | `GET /vuln45/lang?lang=` | `Vuln45HeaderInjection.swift:6` |
