package com.example.vulnapp.vulns;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.nio.file.Files;

@RestController
public class Vuln06PathTraversal {
    private static final String BASE_DIR = "/app/data/";

    @GetMapping("/vuln06/download")
    public ResponseEntity<byte[]> download(@RequestParam String name) throws Exception {
        // VULN:VULN-06:CWE-22:taint path traversal — user input concatenated into a filesystem path
        File f = new File(BASE_DIR + name);
        byte[] data = Files.readAllBytes(f.toPath());
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }
}
