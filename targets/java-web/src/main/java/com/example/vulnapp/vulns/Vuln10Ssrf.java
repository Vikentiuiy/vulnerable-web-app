package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.util.stream.Collectors;

@RestController
public class Vuln10Ssrf {
    @GetMapping("/vuln10/fetch")
    public String fetch(@RequestParam String url) {
        try {
            // VULN:VULN-10:CWE-918:taint SSRF — server fetches an arbitrary user-supplied URL
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(4000); conn.setReadTimeout(4000);
            try (InputStream is = conn.getInputStream()) {
                return new BufferedReader(new InputStreamReader(is)).lines().collect(Collectors.joining("\n"));
            }
        } catch (Exception e) { return "error: " + e; }
    }
}
