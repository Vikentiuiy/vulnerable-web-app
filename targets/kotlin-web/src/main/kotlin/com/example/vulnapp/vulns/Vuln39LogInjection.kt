package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln39LogInjection {

    @GetMapping("/vuln39/note")
    fun note(@RequestParam text: String): String {
        // VULN:VULN-39:CWE-117:taint user input logged without neutralising CR/LF
        println("[audit] user note: $text")
        return "{\"logged\":true}"
    }
}
