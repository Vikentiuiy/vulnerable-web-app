package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Vuln01SqlSearch {
    private final Db db;
    public Vuln01SqlSearch(Db db) { this.db = db; }

    @GetMapping("/vuln01/search")
    public List<Map<String,Object>> search(@RequestParam(defaultValue = "") String q) throws Exception {
        List<Map<String,Object>> out = new ArrayList<>();
        try (Connection c = db.getConnection(); Statement st = c.createStatement()) {
            // VULN:VULN-01:CWE-89:taint SQL injection in product search (UNION extraction)
            String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";
            ResultSet rs = st.executeQuery(sql);
            while (rs.next()) {
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("id", rs.getObject(1)); row.put("name", rs.getObject(2)); row.put("price", rs.getObject(3));
                out.add(row);
            }
        }
        return out;
    }
}
