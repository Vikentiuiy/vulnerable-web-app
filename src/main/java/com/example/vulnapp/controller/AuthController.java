package com.example.vulnapp.controller;

import com.example.vulnapp.util.CryptoUtil;
import com.example.vulnapp.util.Db;
import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Authentication endpoints.
 */
@RestController
public class AuthController {

    private final Db db;
    private final ExploitTracker tracker;
    // VULN:VULN-30:CWE-307 no lockout/throttle — attempts are just counted, never limited
    private final AtomicInteger loginAttempts = new AtomicInteger();

    @Autowired
    public AuthController(Db db, ExploitTracker tracker) {
        this.db = db;
        this.tracker = tracker;
    }

    /**
     * Login. Builds the SQL query by concatenating the username and the MD5 of
     * the password, so `username = admin' -- ` bypasses the password check.
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestParam String username,
                                     @RequestParam String password,
                                     HttpServletResponse response,
                                     HttpSession session) {
        Map<String, Object> out = new HashMap<>();
        // VULN:VULN-30:CWE-307 unlimited authentication attempts (brute-force enabler)
        int attempts = loginAttempts.incrementAndGet();
        if (attempts > 10) {
            tracker.mark("VULN-30", attempts + " login attempts accepted with no lockout");
        }
        boolean injected = username.contains("'") || username.contains("--") || username.matches("(?i).*\\bor\\b.*");
        try (java.sql.Connection conn = db.getConnection();
             Statement st = conn.createStatement()) {
            String hash = CryptoUtil.md5(password);
            // VULN:VULN-02:CWE-89 SQL injection in authentication (login bypass)
            String sql = "SELECT id, username, role FROM users WHERE username = '"
                    + username + "' AND password = '" + hash + "'";
            ResultSet rs = st.executeQuery(sql);
            if (rs.next()) {
                String user = rs.getString("username");
                String role = rs.getString("role");
                session.setAttribute("user", user);
                session.setAttribute("role", role);

                // VULN:VULN-18:CWE-330 predictable session token from java.util.Random
                String token = CryptoUtil.weakToken(username.hashCode());
                // VULN:VULN-17:CWE-614 auth cookie set without HttpOnly/Secure flags
                Cookie c = new Cookie("auth", token);
                c.setPath("/");
                response.addCookie(c);

                if (injected) {
                    tracker.mark("VULN-02", "auth bypass: logged in as " + user + " without a valid password");
                }
                out.put("status", "ok");
                out.put("user", user);
                out.put("role", role);
                out.put("token", token);
            } else {
                out.put("status", "invalid credentials");
            }
        } catch (Exception e) {
            // VULN:VULN-16:CWE-209 raw exception detail returned to the client
            tracker.mark("VULN-16", "stack trace / SQL error leaked: " + e.getClass().getSimpleName());
            out.put("status", "error");
            out.put("error", e.toString());
            out.put("query_hint", "SELECT id, username, role FROM users WHERE username = '" + username + "' ...");
        }
        return out;
    }
}
