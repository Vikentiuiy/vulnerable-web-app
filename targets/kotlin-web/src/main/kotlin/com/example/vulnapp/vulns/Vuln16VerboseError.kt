package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln16VerboseError(private val db: Db) {

    @GetMapping("/vuln16/lookup")
    fun lookup(@RequestParam id: String): String = try {
        db.connection().use { c -> c.createStatement().use { st -> st.executeQuery("SELECT * FROM users WHERE id = $id") } }
        "{\"status\":\"ok\"}"
    } catch (e: Exception) {
        // VULN:VULN-16:CWE-209:logic full exception / stack trace returned to the client
        val sw = java.io.StringWriter(); e.printStackTrace(java.io.PrintWriter(sw)); "error: $e\n$sw"
    }
}
