package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;

@RestController
public class Vuln38Redos {
    // VULN:VULN-38:CWE-1333:logic catastrophically-backtracking regex applied to user input
    private static final Pattern EVIL = Pattern.compile("^(.*a){12}$");

    @GetMapping("/vuln38/validate")
    public String validate(@RequestParam String email) {
        String input = email.length() > 30 ? email.substring(0, 30) : email; // bound worst case
        long t0 = System.currentTimeMillis();
        boolean match = EVIL.matcher(input).matches();
        return "{\"valid\":" + match + ",\"ms\":" + (System.currentTimeMillis() - t0) + "}";
    }
}
