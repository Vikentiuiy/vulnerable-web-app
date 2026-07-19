package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Vuln11SsnExposure {
    private final Db db;
    public Vuln11SsnExposure(Db db) { this.db = db; }

    @GetMapping("/vuln11/profile")
    public Map<String,Object> profile(@RequestParam(defaultValue = "1") int id) throws Exception {
        Map<String,Object> out = new LinkedHashMap<>();
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement("SELECT username, ssn FROM users WHERE id = ?")) {
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                out.put("username", rs.getString("username"));
                // VULN:VULN-11:CWE-200:logic sensitive data (SSN) returned to any caller
                out.put("ssn", rs.getString("ssn"));
            }
        }
        return out;
    }
}
