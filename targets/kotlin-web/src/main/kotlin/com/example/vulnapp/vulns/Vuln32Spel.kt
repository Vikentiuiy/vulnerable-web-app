package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln32Spel {

    @GetMapping("/vuln32/eval")
    fun eval(@RequestParam expr: String): String = try {
        // VULN:VULN-32:CWE-917:taint user-controlled SpEL expression evaluated
        "result: " + org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression(expr).value
    } catch (e: Exception) { "error: $e" }
}
