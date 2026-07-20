# HARNESS (out of scan scope). SQL-focused planted vulns with detection class.
CATALOG = [
    ("VULN-73", "CWE-732", "config", "Excessive DB Privileges (GRANT ALL)", "Config", "db/01_schema.sql"),
    ("VULN-74", "CWE-256", "config", "Unsalted Password Storage", "Storage", "db/01_schema.sql"),
    ("VULN-75", "CWE-312", "config", "Cleartext Storage", "Storage", "db/01_schema.sql"),
    ("VULN-81", "CWE-89", "taint", "SQL Injection (app, direct concat)", "Injection", "GET /vuln81/search?q="),
    ("VULN-82", "CWE-89", "taint", "SQL Injection (auth bypass)", "Injection", "POST /vuln82/login"),
    ("VULN-83", "CWE-89", "taint", "SQL Injection via stored-proc call (cross-boundary)", "Injection", "GET /vuln83/proc?q="),
    ("VULN-84", "CWE-89", "taint", "SQL Injection (f-string)", "Injection", "GET /vuln84/byname?name="),
    ("VULN-85", "CWE-89", "taint", "SQL Injection (str.format)", "Injection", "GET /vuln85/byrole?role="),
    ("VULN-87", "CWE-78", "taint", "OS Command Injection (POSITIVE CONTROL)", "Control", "GET /vuln87/ping?host="),
    ("VULN-89", "CWE-89", "taint", "SQLi in combo endpoint (blind-spot proof)", "Injection", "GET /vuln89/combo?term="),
    ("VULN-90", "CWE-78", "taint", "Cmd injection in combo (POSITIVE CONTROL, same line group)", "Control", "GET /vuln89/combo?term="),
    ("VULN-86", "CWE-89", "taint", "SQL Injection (ORDER BY)", "Injection", "GET /vuln86/sorted?col="),
    ("VULN-88", "CWE-89", "taint", "SQL Injection (numeric context)", "Injection", "GET /vuln88/product?id="),
    ("VULN-92", "CWE-89", "taint", "SQL Injection (LIKE pattern)", "Injection", "GET /vuln92/find?name="),
    ("VULN-93", "CWE-89", "taint", "SQL Injection (UPDATE)", "Injection", "POST /vuln93/rename"),
    ("VULN-94", "CWE-89", "taint", "SQL Injection (IN list)", "Injection", "GET /vuln94/bycat?ids="),
]
