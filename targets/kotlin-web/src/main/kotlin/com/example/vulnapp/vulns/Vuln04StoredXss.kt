package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln04StoredXss {

    private val store = java.util.concurrent.ConcurrentHashMap<String, String>()
    @PostMapping("/vuln04/save")
    fun save(@RequestParam id: String, @RequestParam bio: String): String { store[id] = bio; return "{\"status\":\"saved\"}" }
    @GetMapping("/vuln04/show", produces = ["text/html"])
    fun show(@RequestParam id: String): String =
        // VULN:VULN-04:CWE-79:taint stored XSS: persisted bio rendered unescaped
        "<html><body><div>${store.getOrDefault(id, "")}</div></body></html>"
}
