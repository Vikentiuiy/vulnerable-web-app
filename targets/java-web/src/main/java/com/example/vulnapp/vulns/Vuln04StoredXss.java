package com.example.vulnapp.vulns;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
public class Vuln04StoredXss {
    private final Map<String,String> store = new ConcurrentHashMap<>();

    @PostMapping("/vuln04/save")
    public String save(@RequestParam String id, @RequestParam String bio) {
        store.put(id, bio);           // untrusted bio persisted verbatim
        return "{\"status\":\"saved\"}";
    }

    @GetMapping(value = "/vuln04/show", produces = MediaType.TEXT_HTML_VALUE)
    public String show(@RequestParam String id) {
        String bio = store.getOrDefault(id, "");
        // VULN:VULN-04:CWE-79:taint stored XSS: persisted bio rendered into HTML unescaped
        return "<html><body><div class='bio'>" + bio + "</div></body></html>";
    }
}
