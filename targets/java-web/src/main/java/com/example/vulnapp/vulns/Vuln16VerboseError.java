package com.example.vulnapp.vulns;

import com.example.vulnapp.infra.Db;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.*;

@RestController
public class Vuln16VerboseError {
    private final Db db;
    public Vuln16VerboseError(Db db) { this.db = db; }

    @GetMapping("/vuln16/lookup")
    public String lookup(@RequestParam String id) {
        try (Connection c = db.getConnection(); Statement st = c.createStatement()) {
            st.executeQuery("SELECT * FROM users WHERE id = " + id);
            return "{\"status\":\"ok\"}";
        } catch (Exception e) {
            // VULN:VULN-16:CWE-209:logic full exception / stack trace returned to the client
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return "error: " + e + "\n" + sw;
        }
    }
}
