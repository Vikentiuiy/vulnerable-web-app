# Planted vulnerabilities — sql-app target

SQL-focused target: a thin Flask app + **real MySQL** (schema + stored procedures),
so the SQL sinks have a live HTTP taint source (unlike the standalone `sql` target
which scores 0 for lack of a taint entry point). Includes a **cross-boundary**
case: HTTP input flows through a stored-procedure call into dynamic SQL built
inside the procedure.

Detection classes: taint=3 (app SQLi), config=3 (schema). Headline = engine taint recall.

| ID | CWE | Class | Weakness | Endpoint / File |
|----|-----|-------|----------|-----------------|
| VULN-73 | CWE-732 | config | Excessive DB Privileges (GRANT ALL) | `db/01_schema.sql` |
| VULN-74 | CWE-256 | config | Unsalted Password Storage | `db/01_schema.sql` |
| VULN-75 | CWE-312 | config | Cleartext Storage | `db/01_schema.sql` |
| VULN-81 | CWE-89 | taint | SQL Injection (app, direct concat) | `GET /vuln81/search?q=` |
| VULN-82 | CWE-89 | taint | SQL Injection (auth bypass) | `POST /vuln82/login` |
| VULN-83 | CWE-89 | taint | SQL Injection via stored-proc call (cross-boundary) | `GET /vuln83/proc?q=` |
