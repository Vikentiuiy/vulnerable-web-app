package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln06PathTraversal {

    @GetMapping("/vuln06/download")
    fun download(@RequestParam name: String): ByteArray =
        // VULN:VULN-06:CWE-22:taint path traversal — user input concatenated into a filesystem path
        java.io.File("/app/data/" + name).readBytes()
}
