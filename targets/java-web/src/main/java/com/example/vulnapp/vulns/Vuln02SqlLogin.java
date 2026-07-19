package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import com.example.vulnapp.vulns.crypto.WeakHash;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Vuln02SqlLogin {
    private final Db db;
    public Vuln02SqlLogin(Db db) { this.db = db; }

    @PostMapping("/vuln02/login")
    public Map<String,Object> login(@RequestParam String username, @RequestParam String password) throws Exception {
        Map<String,Object> out = new HashMap<>();
        try (Connection c = db.getConnection(); Statement st = c.createStatement()) {
            String hash = WeakHash.md5(password);
            // VULN:VULN-02:CWE-89:taint SQL injection in authentication (login bypass)
            String sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + hash + "'";
            ResultSet rs = st.executeQuery(sql);
            if (rs.next()) { out.put("status","ok"); out.put("user", rs.getString("username")); out.put("role", rs.getString("role")); }
            else out.put("status","invalid credentials");
        }
        return out;
    }
}
