package com.example.vulnapp.vulns;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.net.URI;

@RestController
public class Vuln24OpenRedirect {
    @GetMapping("/vuln24/redirect")
    public ResponseEntity<Void> redirect(@RequestParam("url") String url) {
        // VULN:VULN-24:CWE-601:taint open redirect — unvalidated redirect target
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
}
