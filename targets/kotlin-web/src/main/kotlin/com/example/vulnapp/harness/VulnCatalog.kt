package com.example.vulnapp.harness

/** HARNESS (out of scan scope). Canonical planted-vuln list with detection class. */
data class Entry(val id:String, val cwe:String, val dclass:String, val title:String, val category:String, val entry:String)

object VulnCatalog {
    val ALL: List<Entry> = listOf(
        Entry("VULN-01","CWE-89","taint","SQL Injection (search)","Injection","GET /vuln01/search?q="),
        Entry("VULN-02","CWE-89","taint","SQL Injection (auth bypass)","Injection","POST /vuln02/login"),
        Entry("VULN-03","CWE-79","taint","Reflected XSS","XSS","GET /vuln03/echo?q="),
        Entry("VULN-04","CWE-79","taint","Stored XSS","XSS","POST /vuln04/save -> /vuln04/show"),
        Entry("VULN-05","CWE-78","taint","OS Command Injection","Injection","GET /vuln05/ping?host="),
        Entry("VULN-06","CWE-22","taint","Path Traversal","Files","GET /vuln06/download?name="),
        Entry("VULN-08","CWE-502","taint","Insecure Deserialization","Injection","POST /vuln08/deserialize"),
        Entry("VULN-09","CWE-611","taint","XXE","Injection","POST /vuln09/xml"),
        Entry("VULN-10","CWE-918","taint","SSRF","Server","GET /vuln10/fetch?url="),
        Entry("VULN-11","CWE-200","logic","Sensitive Data Exposure (SSN)","AccessCtrl","GET /vuln11/profile?id="),
        Entry("VULN-12","CWE-639","logic","IDOR","AccessCtrl","GET /vuln12/account?id="),
        Entry("VULN-13","CWE-327","pattern","Weak Hash (MD5)","Crypto","GET /vuln13/hash?p="),
        Entry("VULN-16","CWE-209","logic","Verbose Error","Server","GET /vuln16/lookup?id="),
        Entry("VULN-17","CWE-614","config","Insecure Cookie","Config","POST /vuln17/login"),
        Entry("VULN-18","CWE-330","pattern","Predictable Token","Crypto","GET /vuln18/token?user="),
        Entry("VULN-19","CWE-256","config","Unsalted Password Storage","Storage","seed schema"),
        Entry("VULN-20","CWE-312","config","Cleartext Storage","Storage","seed schema"),
        Entry("VULN-22","CWE-329","pattern","Static IV","Crypto","GET /vuln22/encrypt?data="),
        Entry("VULN-23","CWE-321","pattern","Hard-coded AES Key","Crypto","GET /vuln22/encrypt?data="),
        Entry("VULN-24","CWE-601","taint","Open Redirect","Server","GET /vuln24/redirect?url="),
        Entry("VULN-25","CWE-470","taint","Unsafe Reflection","Injection","GET /vuln25/plugin?class="),
        Entry("VULN-29","CWE-915","logic","Mass Assignment","AccessCtrl","POST /vuln29/register"),
        Entry("VULN-32","CWE-917","taint","SpEL Injection","Injection","GET /vuln32/eval?expr="),
        Entry("VULN-33","CWE-1236","taint","CSV Injection","Injection","GET /vuln33/export?note="),
        Entry("VULN-34","CWE-942","config","Insecure CORS","Config","GET /vuln34/data (Origin)"),
        Entry("VULN-35","CWE-1021","config","Clickjacking","Config","application.properties"),
        Entry("VULN-36","CWE-190","logic","Integer Overflow","Logic","GET /vuln36/order?price=&qty="),
        Entry("VULN-37","CWE-643","taint","XPath Injection","Injection","GET /vuln37/xlookup?user="),
        Entry("VULN-38","CWE-1333","logic","ReDoS","Logic","GET /vuln38/validate?email="),
        Entry("VULN-39","CWE-117","taint","Log Injection","Server","GET /vuln39/note?text="),
        Entry("VULN-40","CWE-384","logic","Session Fixation","AccessCtrl","GET /vuln40/setsession?sid=")
    )
}
