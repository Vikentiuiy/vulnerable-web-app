package com.example.vulnapp.util;

import java.util.Arrays;
import java.util.List;

/**
 * Canonical list of the 40 planted vulnerabilities, used by the dashboard and
 * the exploit tracker. Ids match the {@code VULN:VULN-xx:CWE-nnn} source markers
 * and {@code checker/reference.sarif}.
 */
public final class VulnCatalog {

    public static final class Entry {
        public final String id, cwe, title, category, entry;
        public Entry(String id, String cwe, String title, String category, String entry) {
            this.id = id; this.cwe = cwe; this.title = title;
            this.category = category; this.entry = entry;
        }
    }

    private VulnCatalog() {}

    public static final List<Entry> ALL = Arrays.asList(
        new Entry("VULN-01", "CWE-89",  "SQL Injection (search)",         "Injection",   "GET /search?q="),
        new Entry("VULN-02", "CWE-89",  "SQL Injection (auth bypass)",    "Injection",   "POST /login"),
        new Entry("VULN-03", "CWE-79",  "Reflected XSS",                  "XSS",         "GET /search?q="),
        new Entry("VULN-04", "CWE-79",  "Stored XSS (bio)",               "XSS",         "POST /profile/update"),
        new Entry("VULN-05", "CWE-78",  "OS Command Injection",           "Injection",   "GET /admin/ping?host="),
        new Entry("VULN-06", "CWE-22",  "Path Traversal",                 "Files",       "GET /files/download?name="),
        new Entry("VULN-07", "CWE-434", "Unrestricted File Upload",       "Files",       "POST /files/upload"),
        new Entry("VULN-08", "CWE-502", "Insecure Deserialization",       "Injection",   "POST /api/deserialize"),
        new Entry("VULN-09", "CWE-611", "XXE",                            "Injection",   "POST /api/xml"),
        new Entry("VULN-10", "CWE-918", "SSRF",                           "Server",      "GET /admin/fetch?url="),
        new Entry("VULN-11", "CWE-200", "Sensitive Data Exposure (SSN)",  "AccessCtrl",  "GET /profile?id="),
        new Entry("VULN-12", "CWE-639", "IDOR / Broken Access Control",   "AccessCtrl",  "GET /profile?id="),
        new Entry("VULN-13", "CWE-327", "Weak Hash (MD5)",                "Crypto",      "source / SQLi chain"),
        new Entry("VULN-14", "CWE-798", "Hard-coded Admin Token",         "Secrets",     "GET /admin/*?token="),
        new Entry("VULN-15", "CWE-306", "Missing Auth (critical fn)",     "AccessCtrl",  "GET /admin/*"),
        new Entry("VULN-16", "CWE-209", "Verbose Error / Info Leak",      "Server",      "POST /login"),
        new Entry("VULN-17", "CWE-614", "Insecure Cookie (no flags)",     "Config",      "POST /login (Set-Cookie)"),
        new Entry("VULN-18", "CWE-330", "Predictable Session Token",      "Crypto",      "POST /login"),
        new Entry("VULN-19", "CWE-256", "Unsalted Password Storage",      "Storage",     "db + SQLi chain"),
        new Entry("VULN-20", "CWE-312", "Cleartext Sensitive Storage",    "Storage",     "db + SQLi chain"),
        new Entry("VULN-21", "CWE-732", "Excessive DB Privileges",        "Config",      "GRANT ALL / SQLi"),
        new Entry("VULN-22", "CWE-329", "Static IV (CBC)",                "Crypto",      "GET /api/encrypt?data="),
        new Entry("VULN-23", "CWE-327", "Hard-coded AES Key",             "Crypto",      "GET /api/encrypt?data="),
        new Entry("VULN-24", "CWE-601", "Open Redirect",                  "Server",      "GET /api/redirect?url="),
        new Entry("VULN-25", "CWE-470", "Unsafe Reflection",              "Injection",   "GET /api/plugin?class="),
        new Entry("VULN-26", "CWE-79",  "DOM-based XSS",                  "XSS",         "/welcome.html#..."),
        new Entry("VULN-27", "CWE-798", "Hard-coded API Key (JS)",        "Secrets",     "GET /js/app.js"),
        new Entry("VULN-28", "CWE-95",  "Client-side eval()",             "XSS",         "/welcome.html?calc="),
        new Entry("VULN-29", "CWE-915", "Mass Assignment (role)",         "AccessCtrl",  "POST /api/register"),
        new Entry("VULN-30", "CWE-307", "No Rate Limiting (brute force)", "AccessCtrl",  "POST /login (xN)"),
        new Entry("VULN-31", "CWE-347", "JWT Signature Not Verified",     "AccessCtrl",  "GET /api/jwt/whoami"),
        new Entry("VULN-32", "CWE-917", "EL / SpEL Injection",            "Injection",   "GET /api/eval?expr="),
        new Entry("VULN-33", "CWE-1236","CSV / Formula Injection",        "Injection",   "GET /api/export?note="),
        new Entry("VULN-34", "CWE-942", "Insecure CORS (reflect+creds)",  "Config",      "GET /api/data (Origin)"),
        new Entry("VULN-35", "CWE-1021","Clickjacking (no XFO)",          "Config",      "any response headers"),
        new Entry("VULN-36", "CWE-190", "Integer Overflow (order total)", "Logic",       "GET /api/order?price=&qty="),
        new Entry("VULN-37", "CWE-643", "XPath Injection",                "Injection",   "GET /api/xlookup?user="),
        new Entry("VULN-38", "CWE-1333","ReDoS (evil regex)",             "Logic",       "GET /api/validate?email="),
        new Entry("VULN-39", "CWE-117", "Log Injection",                  "Server",      "GET /api/note?text="),
        new Entry("VULN-40", "CWE-384", "Session Fixation",               "AccessCtrl",  "GET /api/setsession?sid=")
    );
}
