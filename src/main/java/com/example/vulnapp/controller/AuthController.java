package com.example.vulnapp.controller;

import com.example.vulnapp.util.CryptoUtil;
import com.example.vulnapp.util.Db;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication endpoints.
 */
@RestController
public class AuthController {

    private final Db db;

    @Autowired
    public AuthController(Db db) {
        this.db = db;
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

                out.put("status", "ok");
                out.put("user", user);
                out.put("role", role);
                out.put("token", token);
            } else {
                out.put("status", "invalid credentials");
            }
        } catch (Exception e) {
            // VULN:VULN-16:CWE-209 raw exception detail returned to the client
            out.put("status", "error");
            out.put("error", e.toString());
            out.put("query_hint", "SELECT id, username, role FROM users WHERE username = '" + username + "' ...");
        }
        return out;
    }
}
