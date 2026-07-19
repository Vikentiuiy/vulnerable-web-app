package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln24OpenRedirect {

    @GetMapping("/vuln24/redirect")
    fun redirect(@RequestParam url: String): org.springframework.http.ResponseEntity<Void> {
        // VULN:VULN-24:CWE-601:taint open redirect — unvalidated redirect target
        val h = org.springframework.http.HttpHeaders(); h.location = java.net.URI.create(url)
        return org.springframework.http.ResponseEntity(h, org.springframework.http.HttpStatus.FOUND)
    }
}
