package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln25UnsafeReflection {
    @GetMapping("/vuln25/plugin")
    public String plugin(@RequestParam("class") String className) {
        try {
            // VULN:VULN-25:CWE-470:taint unsafe reflection — class name controlled by the user
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            return "loaded: " + instance.getClass().getName();
        } catch (Exception e) { return "error: " + e; }
    }
}
