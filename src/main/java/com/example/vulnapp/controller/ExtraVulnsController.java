package com.example.vulnapp.controller;

import com.example.vulnapp.util.Db;
import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.nio.charset.StandardCharsets;
import java.sql.Statement;
import java.util.Base64;
import java.util.regex.Pattern;

import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * Additional exploitable endpoints (VULN-29..40).
 */
@RestController
@RequestMapping("/api")
public class ExtraVulnsController {

    private final Db db;
    private final ExploitTracker tracker;

    @Autowired
    public ExtraVulnsController(Db db, ExploitTracker tracker) {
        this.db = db;
        this.tracker = tracker;
    }

    /** VULN-29 CWE-915: mass assignment — caller controls the `role` field. */
    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam(defaultValue = "user") String role) {
        try (java.sql.Connection conn = db.getConnection();
             Statement st = conn.createStatement()) {
            // VULN:VULN-29:CWE-915 role is bound straight from the request (privilege escalation)
            String sql = "INSERT INTO users (username, password, role, bio, ssn) VALUES ('"
                    + username + "', MD5('" + password + "'), '" + role + "', '', '000-00-0000')";
            st.executeUpdate(sql);
            if (!"user".equalsIgnoreCase(role)) {
                tracker.mark("VULN-29", "self-registered with elevated role=" + role);
            }
            return "{\"status\":\"registered\",\"username\":\"" + username + "\",\"role\":\"" + role + "\"}";
        } catch (Exception e) {
            return "{\"status\":\"error\",\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    /** VULN-31 CWE-347: JWT accepted without signature verification (alg:none). */
    @GetMapping("/jwt/whoami")
    public String jwtWhoami(@RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        try {
            String token = auth.replaceFirst("(?i)^Bearer\\s+", "").trim();
            String[] parts = token.split("\\.");
            if (parts.length < 2) return "{\"error\":\"malformed token\"}";
            String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            // VULN:VULN-31:CWE-347 signature is never verified — any token is trusted
            if (header.toLowerCase().contains("\"none\"") || parts.length == 3) {
                tracker.mark("VULN-31", "JWT accepted without verifying signature: " + payload);
            }
            return "{\"trusted\":true,\"claims\":" + payload + "}";
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    /** VULN-32 CWE-917: Spring Expression Language injection. */
    @GetMapping("/eval")
    public String eval(@RequestParam String expr) {
        try {
            // VULN:VULN-32:CWE-917 user-controlled SpEL expression evaluated
            Object value = new SpelExpressionParser().parseExpression(expr).getValue();
            tracker.mark("VULN-32", "evaluated SpEL expression '" + expr + "' => " + value);
            return "result: " + value;
        } catch (Exception e) {
            return "error: " + e;
        }
    }

    /** VULN-33 CWE-1236: CSV / formula injection in an export. */
    @GetMapping(value = "/export", produces = "text/csv")
    public String export(@RequestParam String note) {
        // VULN:VULN-33:CWE-1236 user data written into CSV without neutralising formulas
        if (note.matches("^[=+\\-@].*")) {
            tracker.mark("VULN-33", "CSV formula injected into export: " + note);
        }
        return "id,note\n1," + note + "\n";
    }

    /** VULN-34 CWE-942: CORS reflects any Origin and allows credentials. */
    @GetMapping("/data")
    public String data(@RequestHeader(value = "Origin", required = false) String origin,
                       HttpServletResponse response) {
        if (origin != null && !origin.isEmpty()) {
            // VULN:VULN-34:CWE-942 arbitrary origin reflected + credentials allowed
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            tracker.mark("VULN-34", "CORS reflected arbitrary origin with credentials: " + origin);
        }
        return "{\"secret\":\"account-balance-42000\"}";
    }

    /** VULN-36 CWE-190: integer overflow in an order total. */
    @GetMapping("/order")
    public String order(@RequestParam int price, @RequestParam int qty) {
        // VULN:VULN-36:CWE-190 total computed in a 32-bit int; large values wrap around
        int total = price * qty;
        if (price > 0 && qty > 0 && (long) price * qty != total) {
            tracker.mark("VULN-36", "integer overflow: price=" + price + " qty=" + qty
                    + " total=" + total + " (real=" + ((long) price * qty) + ")");
        }
        return "{\"price\":" + price + ",\"qty\":" + qty + ",\"total\":" + total + "}";
    }

    private static final String USERS_XML =
        "<users>" +
        "<user><name>admin</name><role>admin</role></user>" +
        "<user><name>alice</name><role>user</role></user>" +
        "<user><name>bob</name><role>user</role></user>" +
        "</users>";

    /** VULN-37 CWE-643: XPath injection over an in-memory user document. */
    @GetMapping("/xlookup")
    public String xlookup(@RequestParam String user) {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            // VULN:VULN-37:CWE-643 user input concatenated into an XPath expression
            String query = "/users/user[name='" + user + "']/role";
            NodeList nodes = (NodeList) xpath.evaluate(
                query, new InputSource(new java.io.StringReader(USERS_XML)), XPathConstants.NODESET);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < nodes.getLength(); i++) {
                sb.append(nodes.item(i).getTextContent()).append(",");
            }
            if (user.contains("'") || user.matches("(?i).*\\bor\\b.*")) {
                tracker.mark("VULN-37", "XPath injection returned " + nodes.getLength() + " nodes for user=" + user);
            }
            return "roles: " + sb;
        } catch (Exception e) {
            return "error: " + e;
        }
    }

    // VULN:VULN-38:CWE-1333 catastrophically-backtracking regex applied to user input
    private static final Pattern EVIL = Pattern.compile("^(.*a){20}$");

    /** VULN-38 CWE-1333: ReDoS via an evil regex. */
    @GetMapping("/validate")
    public String validate(@RequestParam String email) {
        String input = email.length() > 30 ? email.substring(0, 30) : email; // bound worst case
        long t0 = System.currentTimeMillis();
        boolean match = EVIL.matcher(input).matches();
        long dt = System.currentTimeMillis() - t0;
        if (dt > 500) {
            tracker.mark("VULN-38", "ReDoS: regex took " + dt + "ms on " + input.length() + "-char input");
        }
        return "{\"valid\":" + match + ",\"ms\":" + dt + "}";
    }

    /** VULN-39 CWE-117: log injection — unsanitised input written to the log. */
    @GetMapping("/note")
    public String note(@RequestParam String text) {
        // VULN:VULN-39:CWE-117 user input logged without neutralising CR/LF (forged log lines)
        System.out.println("[audit] user note: " + text);
        if (text.contains("\n") || text.contains("\r")) {
            tracker.mark("VULN-39", "CRLF in logged value forges log lines: " + text.replace("\n", "\\n"));
        }
        return "{\"logged\":true}";
    }

    /** VULN-40 CWE-384: session fixation — an attacker-supplied session id is adopted. */
    @GetMapping("/setsession")
    public String setSession(@RequestParam String sid,
                             HttpServletRequest request,
                             HttpServletResponse response) {
        // VULN:VULN-40:CWE-384 session id taken from the request and set as-is (never rotated)
        Cookie c = new Cookie("JSESSIONID", sid);
        c.setPath("/");
        response.addCookie(c);
        tracker.mark("VULN-40", "adopted attacker-supplied session id: " + sid);
        return "{\"session\":\"" + sid + "\"}";
    }
}
