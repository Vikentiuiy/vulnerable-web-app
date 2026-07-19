package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln18PredictableToken {

    @GetMapping("/vuln18/token")
    fun token(@RequestParam user: String): String = com.example.vulnapp.vulns.crypto.Secrets.weakToken(user.hashCode().toLong())
}
