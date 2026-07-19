package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln11SsnExposure(private val db: Db) {

    @GetMapping("/vuln11/profile")
    fun profile(@RequestParam(defaultValue = "1") id: Int): Map<String, Any?> {
        db.connection().use { c -> c.prepareStatement("SELECT username, ssn FROM users WHERE id = ?").use { ps ->
            ps.setInt(1, id); val rs = ps.executeQuery()
            // VULN:VULN-11:CWE-200:logic sensitive data (SSN) returned to any caller
            return if (rs.next()) mapOf("username" to rs.getString("username"), "ssn" to rs.getString("ssn")) else emptyMap()
        } }
    }
}
