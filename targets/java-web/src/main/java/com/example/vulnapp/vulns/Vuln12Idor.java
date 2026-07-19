package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Vuln12Idor {
    private final Db db;
    public Vuln12Idor(Db db) { this.db = db; }

    @GetMapping("/vuln12/account")
    public Map<String,Object> account(@RequestParam int id) throws Exception {
        Map<String,Object> out = new LinkedHashMap<>();
        // VULN:VULN-12:CWE-639:logic IDOR — no authorization check tying the session to id
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement("SELECT id, username, role, bio FROM users WHERE id = ?")) {
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) { out.put("id", rs.getInt("id")); out.put("username", rs.getString("username")); out.put("role", rs.getString("role")); out.put("bio", rs.getString("bio")); }
        }
        return out;
    }
}
