package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln25UnsafeReflection {

    @GetMapping("/vuln25/plugin")
    fun plugin(@RequestParam("class") className: String): String = try {
        // VULN:VULN-25:CWE-470:taint unsafe reflection — class name controlled by the user
        val inst = Class.forName(className).getDeclaredConstructor().newInstance()
        "loaded: " + inst.javaClass.name
    } catch (e: Exception) { "error: $e" }
}
