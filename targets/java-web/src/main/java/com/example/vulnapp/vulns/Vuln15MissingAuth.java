package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln15MissingAuth {
    @GetMapping("/vuln15/shutdown")
    public String shutdown() {
        // VULN:VULN-15:CWE-306:logic critical function exposed with no authentication
        return "{\"status\":\"maintenance mode enabled by anonymous caller\"}";
    }
}
