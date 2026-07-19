# Planted vulnerabilities — sql target

7 distinct, **exploitable** SQL weaknesses (MySQL schema + stored procedures).
Includes stored-procedure SQL injection (dynamic SQL), definer-rights privilege
escalation, excessive grants, and insecure storage.

Detection classes: taint=3, config=4. Headline = engine (taint) recall.

Exploit gate: `python3 exploits/exploit_all.py` (needs `vuln-sql-db` healthy).

| ID | CWE | Class | Weakness | File | Line |
|----|-----|-------|----------|------|------|
| VULN-71 | CWE-89 | taint | SQL injection — dynamic SQL concatenated in a st | `02_procs.sql` | 9 |
| VULN-72 | CWE-89 | taint | SQL injection in authentication procedure (login | `02_procs.sql` | 20 |
| VULN-73 | CWE-732 | config | application DB user granted full privileges on e | `01_schema.sql` | 27 |
| VULN-74 | CWE-256 | config | passwords stored as unsalted MD5 | `01_schema.sql` | 8 |
| VULN-75 | CWE-312 | config | secret answer kept in cleartext | `01_schema.sql` | 10 |
| VULN-76 | CWE-250 | config | SQL SECURITY DEFINER runs with definer (root) pr | `02_procs.sql` | 30 |
| VULN-78 | CWE-89 | taint | dynamic table name concatenated into a query | `02_procs.sql` | 41 |
