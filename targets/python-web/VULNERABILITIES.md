# Planted vulnerabilities — python-web target

29 distinct, **exploitable** vulnerabilities (Flask + SQLite).
One file = one primary sink (Blueprint per vuln). Markers `VULN:VULN-xx:CWE-nnn:class`
drive the reference SARIF. Includes Python-specific sinks: SSTI (Jinja2), pickle,
unsafe `yaml.load`, `eval()`.

Detection classes: taint=16, pattern=2, config=5, logic=6.
Headline = engine (taint) recall. See `docs/benchmark-methodology.md`.

| ID | CWE | Class | Title | Endpoint | Sink |
|----|-----|-------|-------|----------|------|
| VULN-01 | CWE-89 | taint | SQL Injection (search) | `GET /vuln01/search?q=` | `vulns/vuln01_sqli.py:9` |
| VULN-02 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln02/login` | `vulns/vuln02_sqli_login.py:12` |
| VULN-03 | CWE-79 | taint | Reflected XSS | `GET /vuln03/echo?q=` | `vulns/vuln03_reflected_xss.py:7` |
| VULN-04 | CWE-79 | taint | Stored XSS | `POST /vuln04/save -> /vuln04/show` | `vulns/vuln04_stored_xss.py:13` |
| VULN-05 | CWE-78 | taint | OS Command Injection | `GET /vuln05/ping?host=` | `vulns/vuln05_cmd.py:8` |
| VULN-06 | CWE-22 | taint | Path Traversal | `GET /vuln06/download?name=` | `vulns/vuln06_path.py:7` |
| VULN-08 | CWE-502 | taint | Insecure Deserialization (pickle) | `POST /vuln08/deserialize` | `vulns/vuln08_pickle.py:8` |
| VULN-09 | CWE-611 | taint | XXE (lxml) | `POST /vuln09/xml` | `vulns/vuln09_xxe.py:8` |
| VULN-10 | CWE-918 | taint | SSRF | `GET /vuln10/fetch?url=` | `vulns/vuln10_ssrf.py:8` |
| VULN-11 | CWE-200 | logic | Sensitive Data Exposure (SSN) | `GET /vuln11/profile?id=` | `vulns/vuln11_ssn.py:10` |
| VULN-12 | CWE-639 | logic | IDOR | `GET /vuln12/account?id=` | `vulns/vuln12_idor.py:9` |
| VULN-13 | CWE-327 | pattern | Weak Hash (MD5) | `GET /vuln13/hash?p=` | `vulns/vuln13_hash.py:8` |
| VULN-16 | CWE-209 | logic | Verbose Error | `GET /vuln16/lookup?id=` | `vulns/vuln16_verbose.py:14` |
| VULN-17 | CWE-614 | config | Insecure Cookie | `GET /vuln17/login?user=` | `vulns/vuln17_cookie.py:10` |
| VULN-18 | CWE-330 | pattern | Predictable Token | `GET /vuln18/token?user=` | `vulns/vuln18_token.py:8` |
| VULN-19 | CWE-256 | config | Unsalted Password Storage | `seed schema` | `app.py:16` |
| VULN-20 | CWE-312 | config | Cleartext Storage | `seed schema` | `app.py:17` |
| VULN-24 | CWE-601 | taint | Open Redirect | `GET /vuln24/redirect?url=` | `vulns/vuln24_redirect.py:7` |
| VULN-29 | CWE-915 | logic | Mass Assignment | `POST /vuln29/register` | `vulns/vuln29_mass_assign.py:12` |
| VULN-32 | CWE-95 | taint | Code Injection (eval) | `GET /vuln32/calc?expr=` | `vulns/vuln32_eval.py:7` |
| VULN-33 | CWE-1236 | taint | CSV Injection | `GET /vuln33/export?note=` | `vulns/vuln33_csv.py:7` |
| VULN-34 | CWE-942 | config | Insecure CORS | `GET /vuln34/data (Origin)` | `vulns/vuln34_cors.py:9` |
| VULN-35 | CWE-1021 | config | Clickjacking | `any response` | `app.py:48` |
| VULN-37 | CWE-643 | taint | XPath Injection | `GET /vuln37/xlookup?user=` | `vulns/vuln37_xpath.py:9` |
| VULN-38 | CWE-1333 | logic | ReDoS | `GET /vuln38/validate?email=` | `vulns/vuln38_redos.py:4` |
| VULN-39 | CWE-117 | taint | Log Injection | `GET /vuln39/note?text=` | `vulns/vuln39_log.py:9` |
| VULN-40 | CWE-384 | logic | Session Fixation | `GET /vuln40/setsession?sid=` | `vulns/vuln40_session.py:8` |
| VULN-41 | CWE-1336 | taint | Server-Side Template Injection (Jinja2) | `GET /vuln41/greet?name=` | `vulns/vuln41_ssti.py:7` |
| VULN-42 | CWE-502 | taint | Unsafe YAML Load | `POST /vuln42/yaml` | `vulns/vuln42_yaml.py:8` |
