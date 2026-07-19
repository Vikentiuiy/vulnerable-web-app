package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln02SqlLogin(private val db: Db) {

    @PostMapping("/vuln02/login")
    fun login(@RequestParam username: String, @RequestParam password: String): Map<String, Any?> {
        db.connection().use { c -> c.createStatement().use { st ->
            val hash = com.example.vulnapp.vulns.crypto.WeakHash.md5(password)
            // VULN:VULN-02:CWE-89:taint SQL injection in authentication (login bypass)
            val rs = st.executeQuery("SELECT id, username, role FROM users WHERE username = '$username' AND password = '$hash'")
            return if (rs.next()) mapOf("status" to "ok", "user" to rs.getString("username"), "role" to rs.getString("role"))
                   else mapOf("status" to "invalid")
        } }
    }
}
