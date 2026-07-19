package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln03ReflectedXss {

    @GetMapping("/vuln03/echo", produces = ["text/html"])
    fun echo(@RequestParam(defaultValue = "") q: String): String =
        // VULN:VULN-03:CWE-79:taint reflected XSS: input echoed into HTML unescaped
        "<html><body><h3>You searched for: $q</h3></body></html>"
}
