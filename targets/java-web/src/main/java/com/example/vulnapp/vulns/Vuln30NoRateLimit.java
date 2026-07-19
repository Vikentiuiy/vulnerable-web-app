package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import com.example.vulnapp.vulns.crypto.WeakHash;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.*;

@RestController
public class Vuln30NoRateLimit {
    private final Db db;
    public Vuln30NoRateLimit(Db db) { this.db = db; }

    // VULN:VULN-30:CWE-307:logic no lockout/throttle — unlimited authentication attempts
    @PostMapping("/vuln30/login")
    public Map<String,Object> login(@RequestParam String username, @RequestParam String password) throws Exception {
        Map<String,Object> out = new HashMap<>();
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(
                "SELECT username FROM users WHERE username = ? AND password = ?")) {
            ps.setString(1, username); ps.setString(2, WeakHash.md5(password));
            out.put("status", ps.executeQuery().next() ? "ok" : "invalid");
        }
        return out;
    }
}
