package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln38Redos {

    private val evil = java.util.regex.Pattern.compile("^(.*a){12}$")
    @GetMapping("/vuln38/validate")
    fun validate(@RequestParam email: String): String {
        // VULN:VULN-38:CWE-1333:logic catastrophically-backtracking regex applied to user input
        val input = if (email.length > 30) email.substring(0, 30) else email
        val t0 = System.currentTimeMillis()
        val match = evil.matcher(input).matches()
        return "{\"valid\":$match,\"ms\":${System.currentTimeMillis() - t0}}"
    }
}
