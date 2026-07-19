package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln12Idor(private val db: Db) {

    @GetMapping("/vuln12/account")
    fun account(@RequestParam id: Int): Map<String, Any?> {
        // VULN:VULN-12:CWE-639:logic IDOR — no authorization check tying the session to id
        db.connection().use { c -> c.prepareStatement("SELECT id, username, role FROM users WHERE id = ?").use { ps ->
            ps.setInt(1, id); val rs = ps.executeQuery()
            return if (rs.next()) mapOf("id" to rs.getInt("id"), "username" to rs.getString("username"), "role" to rs.getString("role")) else emptyMap()
        } }
    }
}
