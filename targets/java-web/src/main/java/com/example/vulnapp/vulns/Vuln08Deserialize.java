package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
public class Vuln08Deserialize {
    @PostMapping("/vuln08/deserialize")
    public String deserialize(@RequestBody String base64) {
        try {
            byte[] raw = Base64.getDecoder().decode(base64.trim());
            // VULN:VULN-08:CWE-502:taint deserialization of untrusted data (RCE via gadget chains)
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw));
            Object obj = ois.readObject();
            return "deserialized: " + obj.getClass().getName();
        } catch (Exception e) { return "error: " + e; }
    }
}
