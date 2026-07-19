package com.example.vulnapp.vulns;

import com.example.vulnapp.vulns.crypto.AesCipher;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln22Encrypt {
    @GetMapping("/vuln22/encrypt")
    public String encrypt(@RequestParam String data) {
        // hard-coded key (VULN-23) + static IV (VULN-22) sinks live in AesCipher
        return AesCipher.encrypt(data);
    }
}
