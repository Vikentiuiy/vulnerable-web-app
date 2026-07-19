package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln05CmdInjection {

    @GetMapping("/vuln05/ping")
    fun ping(@RequestParam host: String): String {
        // VULN:VULN-05:CWE-78:taint OS command injection — host concatenated into a shell command
        val p = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", "ping -c 1 $host"))
        return p.inputStream.bufferedReader().readText() + p.errorStream.bufferedReader().readText()
    }
}
