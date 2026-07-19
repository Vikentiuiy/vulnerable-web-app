package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
public class Vuln29MassAssignment {
    private final Db db;
    public Vuln29MassAssignment(Db db) { this.db = db; }

    @PostMapping("/vuln29/register")
    public String register(@RequestParam String username, @RequestParam String password,
                           @RequestParam(defaultValue = "user") String role) {
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(
                "INSERT INTO users (username, password, role, bio, ssn) VALUES (?, MD5(?), ?, '', '000-00-0000')")) {
            ps.setString(1, username); ps.setString(2, password);
            // VULN:VULN-29:CWE-915:logic mass assignment — caller-controlled role bound directly
            ps.setString(3, role);
            ps.executeUpdate();
            return "{\"status\":\"registered\",\"role\":\"" + role + "\"}";
        } catch (Exception e) { return "{\"status\":\"error\"}"; }
    }
}
