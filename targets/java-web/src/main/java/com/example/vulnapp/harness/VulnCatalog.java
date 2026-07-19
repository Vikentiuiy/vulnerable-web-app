package com.example.vulnapp.harness;

import java.util.Arrays;
import java.util.List;

/**
 * HARNESS (out of scan scope). Canonical list of the 40 planted vulnerabilities:
 * id, CWE, detection class, one dedicated 1:1 endpoint each. Ids match the
 * {@code VULN:VULN-xx:CWE-nnn:class} source markers and reference.sarif.
 *
 * detection class: taint | pattern | config | sca | logic
 *   (see docs/benchmark-methodology.md — headline metric is engine recall over
 *    the taint-class vulns).
 */
public final class VulnCatalog {

    public static final class Entry {
        public final String id, cwe, dclass, title, category, entry;
        public Entry(String id, String cwe, String dclass, String title, String category, String entry) {
            this.id = id; this.cwe = cwe; this.dclass = dclass;
            this.title = title; this.category = category; this.entry = entry;
        }
    }

    private VulnCatalog() {}

    public static final List<Entry> ALL = Arrays.asList(
        new Entry("VULN-01","CWE-89","taint","SQL Injection (search)","Injection","GET /vuln01/search?q="),
        new Entry("VULN-02","CWE-89","taint","SQL Injection (auth bypass)","Injection","POST /vuln02/login"),
        new Entry("VULN-03","CWE-79","taint","Reflected XSS","XSS","GET /vuln03/echo?q="),
        new Entry("VULN-04","CWE-79","taint","Stored XSS","XSS","POST /vuln04/save -> GET /vuln04/show"),
        new Entry("VULN-05","CWE-78","taint","OS Command Injection","Injection","GET /vuln05/ping?host="),
        new Entry("VULN-06","CWE-22","taint","Path Traversal","Files","GET /vuln06/download?name="),
        new Entry("VULN-07","CWE-434","taint","Unrestricted File Upload","Files","POST /vuln07/upload"),
        new Entry("VULN-08","CWE-502","taint","Insecure Deserialization","Injection","POST /vuln08/deserialize"),
        new Entry("VULN-09","CWE-611","taint","XXE","Injection","POST /vuln09/xml"),
        new Entry("VULN-10","CWE-918","taint","SSRF","Server","GET /vuln10/fetch?url="),
        new Entry("VULN-11","CWE-200","logic","Sensitive Data Exposure (SSN)","AccessCtrl","GET /vuln11/profile?id="),
        new Entry("VULN-12","CWE-639","logic","IDOR / Broken Access Control","AccessCtrl","GET /vuln12/account?id="),
        new Entry("VULN-13","CWE-327","pattern","Weak Hash (MD5)","Crypto","GET /vuln13/hash?p="),
        new Entry("VULN-14","CWE-798","pattern","Hard-coded Admin Token","Secrets","GET /vuln14/admin?token="),
        new Entry("VULN-15","CWE-306","logic","Missing Auth (critical fn)","AccessCtrl","GET /vuln15/shutdown"),
        new Entry("VULN-16","CWE-209","logic","Verbose Error / Info Leak","Server","GET /vuln16/lookup?id="),
        new Entry("VULN-17","CWE-614","config","Insecure Cookie (no flags)","Config","POST /vuln17/login"),
        new Entry("VULN-18","CWE-330","pattern","Predictable Session Token","Crypto","GET /vuln18/token?user="),
        new Entry("VULN-19","CWE-256","config","Unsalted Password Storage","Storage","db/init.sql"),
        new Entry("VULN-20","CWE-312","config","Cleartext Sensitive Storage","Storage","db/init.sql"),
        new Entry("VULN-21","CWE-732","config","Excessive DB Privileges","Config","db/init.sql (GRANT ALL)"),
        new Entry("VULN-22","CWE-329","pattern","Static IV (CBC)","Crypto","GET /vuln22/encrypt?data="),
        new Entry("VULN-23","CWE-321","pattern","Hard-coded AES Key","Crypto","GET /vuln22/encrypt?data="),
        new Entry("VULN-24","CWE-601","taint","Open Redirect","Server","GET /vuln24/redirect?url="),
        new Entry("VULN-25","CWE-470","taint","Unsafe Reflection","Injection","GET /vuln25/plugin?class="),
        new Entry("VULN-26","CWE-79","taint","DOM-based XSS","XSS","/welcome.html#name="),
        new Entry("VULN-27","CWE-798","pattern","Hard-coded API Key (JS)","Secrets","GET /js/app.js"),
        new Entry("VULN-28","CWE-95","taint","Client-side eval()","XSS","/welcome.html?calc="),
        new Entry("VULN-29","CWE-915","logic","Mass Assignment (role)","AccessCtrl","POST /vuln29/register"),
        new Entry("VULN-30","CWE-307","logic","No Rate Limiting","AccessCtrl","POST /vuln30/login (xN)"),
        new Entry("VULN-31","CWE-347","logic","JWT Signature Not Verified","AccessCtrl","GET /vuln31/whoami"),
        new Entry("VULN-32","CWE-917","taint","EL / SpEL Injection","Injection","GET /vuln32/eval?expr="),
        new Entry("VULN-33","CWE-1236","taint","CSV / Formula Injection","Injection","GET /vuln33/export?note="),
        new Entry("VULN-34","CWE-942","config","Insecure CORS","Config","GET /vuln34/data (Origin)"),
        new Entry("VULN-35","CWE-1021","config","Clickjacking (no XFO)","Config","application.properties"),
        new Entry("VULN-36","CWE-190","logic","Integer Overflow (order)","Logic","GET /vuln36/order?price=&qty="),
        new Entry("VULN-37","CWE-643","taint","XPath Injection","Injection","GET /vuln37/xlookup?user="),
        new Entry("VULN-38","CWE-1333","logic","ReDoS (evil regex)","Logic","GET /vuln38/validate?email="),
        new Entry("VULN-39","CWE-117","taint","Log Injection","Server","GET /vuln39/note?text="),
        new Entry("VULN-40","CWE-384","logic","Session Fixation","AccessCtrl","GET /vuln40/setsession?sid=")
    );
}
