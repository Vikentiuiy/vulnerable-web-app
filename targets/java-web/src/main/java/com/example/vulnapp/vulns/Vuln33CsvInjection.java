package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln33CsvInjection {
    @GetMapping(value = "/vuln33/export", produces = "text/csv")
    public String export(@RequestParam String note) {
        // VULN:VULN-33:CWE-1236:taint user data written into CSV without neutralising formulas
        return "id,note\n1," + note + "\n";
    }
}
