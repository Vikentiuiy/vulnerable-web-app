package com.example.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.stream.Collectors;

/**
 * "Admin" tools. These are critical functions with NO authentication — anyone
 * who can reach the endpoint can run them.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    /**
     * Network diagnostics: ping a host. The host parameter is concatenated into
     * a shell command, so `8.8.8.8; id` runs arbitrary commands.
     */
    @GetMapping("/ping")
    public String ping(@RequestParam String host) {
        // VULN:VULN-15:CWE-306 missing authentication for a critical function
        try {
            // VULN:VULN-05:CWE-78 OS command injection — host passed to a shell
            String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};
            Process p = Runtime.getRuntime().exec(cmd);
            String out = new BufferedReader(new InputStreamReader(p.getInputStream()))
                    .lines().collect(Collectors.joining("\n"));
            String err = new BufferedReader(new InputStreamReader(p.getErrorStream()))
                    .lines().collect(Collectors.joining("\n"));
            return out + "\n" + err;
        } catch (Exception e) {
            return "error: " + e;
        }
    }

    /**
     * "URL preview" — fetch a URL server-side and return its body. No allow-list,
     * so it will happily hit internal services / cloud metadata endpoints.
     */
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        // VULN:VULN-10:CWE-918 SSRF — server fetches an arbitrary user-supplied URL
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);
            try (InputStream is = conn.getInputStream()) {
                return new BufferedReader(new InputStreamReader(is))
                        .lines().collect(Collectors.joining("\n"));
            }
        } catch (Exception e) {
            return "error: " + e;
        }
    }
}
