package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln22Encrypt {

    @GetMapping("/vuln22/encrypt")
    fun encrypt(@RequestParam data: String): String = com.example.vulnapp.vulns.crypto.AesCipher.encrypt(data)
}
