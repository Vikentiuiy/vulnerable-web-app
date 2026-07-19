package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln34Cors {

    @GetMapping("/vuln34/data")
    fun data(@RequestHeader(value = "Origin", required = false) origin: String?,
             response: javax.servlet.http.HttpServletResponse): String {
        if (!origin.isNullOrEmpty()) {
            // VULN:VULN-34:CWE-942:config arbitrary Origin reflected + credentials allowed
            response.setHeader("Access-Control-Allow-Origin", origin)
            response.setHeader("Access-Control-Allow-Credentials", "true")
        }
        return "{\"secret\":\"account-balance-42000\"}"
    }
}
