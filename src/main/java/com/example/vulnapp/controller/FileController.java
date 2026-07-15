package com.example.vulnapp.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * File download / upload endpoints.
 */
@RestController
public class FileController {

    private static final String BASE_DIR = "/app/data/";

    /**
     * Download a file by name. The name is joined to BASE_DIR with no
     * canonicalisation, so `../../secret.txt` escapes the directory.
     */
    @GetMapping("/files/download")
    public ResponseEntity<byte[]> download(@RequestParam String name) throws Exception {
        // VULN:VULN-06:CWE-22 path traversal — user input concatenated into a filesystem path
        File f = new File(BASE_DIR + name);
        byte[] data = Files.readAllBytes(f.toPath());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(data);
    }

    /**
     * Upload a file. No type/size/extension validation, and the client-supplied
     * filename is used verbatim (so it can also traverse out of the upload dir).
     */
    @PostMapping("/files/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        String filename = file.getOriginalFilename();
        // VULN:VULN-07:CWE-434 unrestricted file upload (+ CWE-22 filename traversal)
        Path dest = Paths.get(BASE_DIR, filename);
        Files.createDirectories(dest.getParent());
        Files.write(dest, file.getBytes());
        return "{\"status\":\"stored\",\"path\":\"" + dest + "\"}";
    }
}
