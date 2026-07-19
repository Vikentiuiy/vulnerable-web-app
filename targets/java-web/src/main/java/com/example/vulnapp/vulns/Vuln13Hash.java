package com.example.vulnapp.vulns;

import com.example.vulnapp.vulns.crypto.WeakHash;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln13Hash {
    @GetMapping("/vuln13/hash")
    public String hash(@RequestParam String p) {
        // weak-hash sink lives in WeakHash.md5 (VULN-13); this endpoint exercises it
        return WeakHash.md5(p);
    }
}
