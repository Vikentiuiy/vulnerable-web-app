package com.example.vulnapp.controller;

import com.example.vulnapp.util.Db;
import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.sql.ResultSet;
import java.sql.Statement;

/**
 * User profile view + bio update.
 * <ul>
 *   <li>IDOR: any profile can be viewed by numeric id with no ownership check.</li>
 *   <li>Stored XSS: the bio is saved and later rendered unescaped.</li>
 * </ul>
 */
@Controller
public class ProfileController {

    private final Db db;
    private final ExploitTracker tracker;

    @Autowired
    public ProfileController(Db db, ExploitTracker tracker) {
        this.db = db;
        this.tracker = tracker;
    }

    @GetMapping("/profile")
    public String profile(@RequestParam(defaultValue = "1") String id, Model model) {
        if (id.matches("(?is).*(union|select|--|'|information_schema).*")) {
            tracker.mark("VULN-01", "SQL injection payload processed in /profile id=" + id);
        }
        try (java.sql.Connection conn = db.getConnection();
             Statement st = conn.createStatement()) {
            // VULN:VULN-12:CWE-639 IDOR — no authorization check tying the session to `id`
            // VULN:VULN-01:CWE-89 (also SQL-injectable — id concatenated directly)
            String sql = "SELECT id, username, role, bio, ssn FROM users WHERE id = " + id;
            ResultSet rs = st.executeQuery(sql);
            if (rs.next()) {
                model.addAttribute("id", rs.getObject("id"));
                model.addAttribute("username", rs.getString("username"));
                model.addAttribute("role", rs.getString("role"));
                // VULN:VULN-04:CWE-79 stored XSS — bio rendered with th:utext in the template
                model.addAttribute("bio", rs.getString("bio"));
                // VULN:VULN-11:CWE-200 sensitive data (SSN) exposed to any viewer
                model.addAttribute("ssn", rs.getString("ssn"));
                // No auth check happened at all: viewing any id already proves IDOR + exposure.
                tracker.mark("VULN-12", "viewed user id=" + rs.getObject("id") + " with no authorization check");
                if (rs.getString("ssn") != null) {
                    tracker.mark("VULN-11", "SSN exposed for " + rs.getString("username") + ": " + rs.getString("ssn"));
                }
            } else {
                model.addAttribute("username", "(not found)");
            }
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
        }
        return "profile";
    }

    /** Update a user's bio — the stored-XSS source. */
    @PostMapping("/profile/update")
    @ResponseBody
    public String update(@RequestParam String id, @RequestParam String bio) {
        if (bio.matches("(?is).*(<script|onerror=|onload=|<img|<svg).*")) {
            tracker.mark("VULN-04", "stored XSS payload persisted in bio: " + bio);
        }
        if (id.matches("(?is).*(union|select|--|').*")) {
            tracker.mark("VULN-01", "SQL injection payload processed in /profile/update id=" + id);
        }
        try (java.sql.Connection conn = db.getConnection();
             Statement st = conn.createStatement()) {
            // VULN:VULN-04:CWE-79 stored XSS source + VULN:VULN-01:CWE-89 SQLi (bio/id concatenated)
            String sql = "UPDATE users SET bio = '" + bio + "' WHERE id = " + id;
            st.executeUpdate(sql);
            return "{\"status\":\"updated\"}";
        } catch (Exception e) {
            return "{\"status\":\"error\",\"error\":\"" + e.getMessage() + "\"}";
        }
    }
}
