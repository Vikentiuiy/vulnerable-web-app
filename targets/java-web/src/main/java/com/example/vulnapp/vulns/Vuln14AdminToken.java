package com.example.vulnapp.vulns;

import com.example.vulnapp.vulns.crypto.Secrets;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln14AdminToken {
    @GetMapping("/vuln14/admin")
    public String admin(@RequestParam(defaultValue = "") String token) {
        // hard-coded credential compared here (constant declared in Secrets, VULN-14)
        if (Secrets.ADMIN_TOKEN.equals(token)) return "{\"admin\":true}";
        return "{\"admin\":false}";
    }
}
