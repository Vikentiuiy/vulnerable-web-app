package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class Vuln31JwtNone {
    @GetMapping("/vuln31/whoami")
    public String whoami(@RequestHeader(value = "Authorization", defaultValue = "") String auth) {
        try {
            String token = auth.replaceFirst("(?i)^Bearer\\s+", "").trim();
            String[] parts = token.split("\\.");
            if (parts.length < 2) return "{\"error\":\"malformed\"}";
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            // VULN:VULN-31:CWE-347:logic JWT signature never verified — any token trusted
            return "{\"trusted\":true,\"claims\":" + payload + "}";
        } catch (Exception e) { return "{\"error\":\"bad token\"}"; }
    }
}
