# Planted vulnerabilities — sql-app target

16 distinct, **exploitable** vulnerabilities.
Detection classes: taint=13, pattern=0, config=3, logic=0. Headline = engine (taint) recall.

| ID | CWE | Class | Title | Endpoint | Sink |
|----|-----|-------|-------|----------|------|
| VULN-73 | CWE-732 | config | Excessive DB Privileges (GRANT ALL) | `db/01_schema.sql` | `db/01_schema.sql:27` |
| VULN-74 | CWE-256 | config | Unsalted Password Storage | `db/01_schema.sql` | `db/01_schema.sql:8` |
| VULN-75 | CWE-312 | config | Cleartext Storage | `db/01_schema.sql` | `db/01_schema.sql:10` |
| VULN-81 | CWE-89 | taint | SQL Injection (app, direct concat) | `GET /vuln81/search?q=` | `vulns/vuln81_sqli.py:12` |
| VULN-82 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln82/login` | `vulns/vuln82_login.py:13` |
| VULN-83 | CWE-89 | taint | SQL Injection via stored-proc call (cross-boundary) | `GET /vuln83/proc?q=` | `vulns/vuln83_proc.py:12` |
| VULN-84 | CWE-89 | taint | SQL Injection (f-string) | `GET /vuln84/byname?name=` | `vulns/vuln84_fstring.py:12` |
| VULN-85 | CWE-89 | taint | SQL Injection (str.format) | `GET /vuln85/byrole?role=` | `vulns/vuln85_format.py:12` |
| VULN-86 | CWE-89 | taint | SQL Injection (ORDER BY) | `GET /vuln86/sorted?col=` | `vulns/vuln86_orderby.py:9` |
| VULN-87 | CWE-78 | taint | OS Command Injection (POSITIVE CONTROL) | `GET /vuln87/ping?host=` | `vulns/vuln87_cmd_control.py:15` |
| VULN-88 | CWE-89 | taint | SQL Injection (numeric context) | `GET /vuln88/product?id=` | `vulns/vuln88_numeric.py:9` |
| VULN-89 | CWE-89 | taint | SQLi in combo endpoint (blind-spot proof) | `GET /vuln89/combo?term=` | `vulns/vuln89_combo.py:21` |
| VULN-90 | CWE-78 | taint | Cmd injection in combo (POSITIVE CONTROL, same line group) | `GET /vuln89/combo?term=` | `vulns/vuln89_combo.py:17` |
| VULN-92 | CWE-89 | taint | SQL Injection (LIKE pattern) | `GET /vuln92/find?name=` | `vulns/vuln92_like.py:9` |
| VULN-93 | CWE-89 | taint | SQL Injection (UPDATE) | `POST /vuln93/rename` | `vulns/vuln93_update.py:9` |
| VULN-94 | CWE-89 | taint | SQL Injection (IN list) | `GET /vuln94/bycat?ids=` | `vulns/vuln94_inclause.py:9` |
