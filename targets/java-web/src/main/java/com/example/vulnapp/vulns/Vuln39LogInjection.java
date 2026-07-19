package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln39LogInjection {
    @GetMapping("/vuln39/note")
    public String note(@RequestParam String text) {
        // VULN:VULN-39:CWE-117:taint user input logged without neutralising CR/LF (forged log lines)
        System.out.println("[audit] user note: " + text);
        return "{\"logged\":true}";
    }
}
