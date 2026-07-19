package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln29MassAssignment(private val db: Db) {

    @PostMapping("/vuln29/register")
    fun register(@RequestParam username: String, @RequestParam password: String,
                 @RequestParam(defaultValue = "user") role: String): String {
        db.connection().use { c -> c.prepareStatement("INSERT INTO users (username,password,role,bio,ssn) VALUES (?,?,?,'','000-00-0000')").use { ps ->
            ps.setString(1, username); ps.setString(2, com.example.vulnapp.vulns.crypto.WeakHash.md5(password))
            // VULN:VULN-29:CWE-915:logic mass assignment — caller-controlled role bound directly
            ps.setString(3, role); ps.executeUpdate()
        } }
        return "{\"status\":\"registered\",\"role\":\"$role\"}"
    }
}
