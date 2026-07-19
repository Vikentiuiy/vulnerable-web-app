package com.example.vulnapp.vulns;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln03ReflectedXss {
    @GetMapping(value = "/vuln03/echo", produces = MediaType.TEXT_HTML_VALUE)
    public String echo(@RequestParam(defaultValue = "") String q) {
        // VULN:VULN-03:CWE-79:taint reflected XSS: user input echoed into HTML unescaped
        return "<html><body><h3>You searched for: " + q + "</h3></body></html>";
    }
}
