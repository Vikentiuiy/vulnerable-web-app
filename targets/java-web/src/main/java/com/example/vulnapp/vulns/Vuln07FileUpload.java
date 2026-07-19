package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.nio.file.*;

@RestController
public class Vuln07FileUpload {
    private static final String BASE_DIR = "/app/data/";

    @PostMapping("/vuln07/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        String filename = file.getOriginalFilename();
        // VULN:VULN-07:CWE-434:taint unrestricted file upload — client filename used verbatim, no type check
        Path dest = Paths.get(BASE_DIR, filename);
        Files.createDirectories(dest.getParent());
        Files.write(dest, file.getBytes());
        return "{\"status\":\"stored\",\"path\":\"" + dest + "\"}";
    }
}
