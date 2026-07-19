package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln33CsvInjection {

    @GetMapping("/vuln33/export", produces = ["text/csv"])
    fun export(@RequestParam note: String): String =
        // VULN:VULN-33:CWE-1236:taint user data written into CSV without neutralising formulas
        "id,note\n1,$note\n"
}
