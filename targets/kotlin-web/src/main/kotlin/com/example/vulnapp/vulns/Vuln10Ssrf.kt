package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln10Ssrf {

    @GetMapping("/vuln10/fetch")
    fun fetch(@RequestParam url: String): String = try {
        // VULN:VULN-10:CWE-918:taint SSRF — server fetches an arbitrary user-supplied URL
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.connectTimeout = 4000; conn.readTimeout = 4000
        conn.inputStream.bufferedReader().readText()
    } catch (e: Exception) { "error: $e" }
}
