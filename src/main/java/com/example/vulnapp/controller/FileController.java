package com.example.vulnapp.controller;

import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
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

    private final ExploitTracker tracker;

    @Autowired
    public FileController(ExploitTracker tracker) {
        this.tracker = tracker;
    }

    /**
     * Download a file by name. The name is joined to BASE_DIR with no
     * canonicalisation, so `../../secret.txt` escapes the directory.
     */
    @GetMapping("/files/download")
    public ResponseEntity<byte[]> download(@RequestParam String name) throws Exception {
        // VULN:VULN-06:CWE-22 path traversal — user input concatenated into a filesystem path
        File f = new File(BASE_DIR + name);
        byte[] data = Files.readAllBytes(f.toPath());
        if (name.contains("..") || name.startsWith("/")) {
            tracker.mark("VULN-06", "path traversal read outside base dir: " + f.getPath());
        }
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
        tracker.mark("VULN-07", "stored unrestricted upload: " + filename + " (" + file.getSize() + " bytes)");
        return "{\"status\":\"stored\",\"path\":\"" + dest + "\"}";
    }
}
