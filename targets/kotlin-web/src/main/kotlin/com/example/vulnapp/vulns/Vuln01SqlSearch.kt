package com.example.vulnapp.vulns

import com.example.vulnapp.infra.Db
import org.springframework.web.bind.annotation.*


@RestController
class Vuln01SqlSearch(private val db: Db) {

    @GetMapping("/vuln01/search")
    fun search(@RequestParam(defaultValue = "") q: String): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        db.connection().use { c -> c.createStatement().use { st ->
            // VULN:VULN-01:CWE-89:taint SQL injection in product search
            val rs = st.executeQuery("SELECT id, name, price FROM products WHERE name LIKE '%$q%'")
            while (rs.next()) out.add(mapOf("id" to rs.getObject(1), "name" to rs.getObject(2), "price" to rs.getObject(3)))
        } }
        return out
    }
}
