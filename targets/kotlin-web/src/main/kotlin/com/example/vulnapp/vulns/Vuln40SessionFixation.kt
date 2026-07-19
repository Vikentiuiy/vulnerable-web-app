package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln40SessionFixation {

    @GetMapping("/vuln40/setsession")
    fun setSession(@RequestParam sid: String, response: javax.servlet.http.HttpServletResponse): String {
        // VULN:VULN-40:CWE-384:logic session id taken from the request and set as-is
        val c = javax.servlet.http.Cookie("JSESSIONID", sid); c.path = "/"; response.addCookie(c)
        return "{\"session\":\"$sid\"}"
    }
}
