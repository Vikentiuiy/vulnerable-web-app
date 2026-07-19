package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;

@RestController
public class Vuln34Cors {
    @GetMapping("/vuln34/data")
    public String data(@RequestHeader(value = "Origin", required = false) String origin, HttpServletResponse response) {
        if (origin != null && !origin.isEmpty()) {
            // VULN:VULN-34:CWE-942:config arbitrary Origin reflected + credentials allowed
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
        return "{\"secret\":\"account-balance-42000\"}";
    }
}
