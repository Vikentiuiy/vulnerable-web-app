package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln13Hash {

    @GetMapping("/vuln13/hash")
    fun hash(@RequestParam p: String): String = com.example.vulnapp.vulns.crypto.WeakHash.md5(p)
}
