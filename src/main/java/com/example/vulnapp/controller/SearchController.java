package com.example.vulnapp.controller;

import com.example.vulnapp.util.Db;
import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Product search. Both a SQL-injection sink (query built by concatenation) and
 * a reflected-XSS sink (the raw query term is rendered unescaped by the view).
 */
@Controller
public class SearchController {

    private final Db db;
    private final ExploitTracker tracker;

    @Autowired
    public SearchController(Db db, ExploitTracker tracker) {
        this.db = db;
        this.tracker = tracker;
    }

    @GetMapping("/search")
    public String search(@RequestParam(defaultValue = "") String q, Model model) {
        List<Map<String, Object>> results = new ArrayList<>();
        if (q.matches("(?is).*(union|select|--|'\\s*or|0x[0-9a-f]+|information_schema).*")) {
            tracker.mark("VULN-01", "SQL injection payload processed in /search: " + q);
        }
        if (q.matches("(?is).*(<script|onerror=|onload=|<img|<svg).*")) {
            tracker.mark("VULN-03", "reflected XSS payload echoed unescaped: " + q);
        }
        try (java.sql.Connection conn = db.getConnection();
             Statement st = conn.createStatement()) {
            // VULN:VULN-01:CWE-89 SQL injection in product search (UNION-based extraction possible)
            String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";
            ResultSet rs = st.executeQuery(sql);
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", rs.getObject(1));
                row.put("name", rs.getObject(2));
                row.put("price", rs.getObject(3));
                results.add(row);
            }
        } catch (Exception e) {
            // VULN:VULN-16:CWE-209 SQL error text surfaced to the page
            tracker.mark("VULN-16", "SQL error surfaced to page: " + e.getClass().getSimpleName());
            model.addAttribute("error", e.getMessage());
        }
        // VULN:VULN-03:CWE-79 reflected XSS: `q` is echoed into the page via th:utext (unescaped)
        model.addAttribute("q", q);
        model.addAttribute("results", results);
        return "search";
    }
}
