package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletResponse

@RestController
class Vuln17InsecureCookie {

    @PostMapping("/vuln17/login")
    fun login(@RequestParam username: String, response: javax.servlet.http.HttpServletResponse): Map<String, Any?> {
        val token = com.example.vulnapp.vulns.crypto.Secrets.weakToken(username.hashCode().toLong())
        // VULN:VULN-17:CWE-614:config auth cookie set without HttpOnly/Secure flags
        val c = javax.servlet.http.Cookie("auth", token); c.path = "/"; response.addCookie(c)
        return mapOf("status" to "ok", "token" to token)
    }
}
