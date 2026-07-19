package com.example.vulnapp.vulns;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln32Spel {
    @GetMapping("/vuln32/eval")
    public String eval(@RequestParam String expr) {
        try {
            // VULN:VULN-32:CWE-917:taint user-controlled SpEL expression evaluated
            Object value = new SpelExpressionParser().parseExpression(expr).getValue();
            return "result: " + value;
        } catch (Exception e) { return "error: " + e; }
    }
}
