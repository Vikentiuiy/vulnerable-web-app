package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.stream.Collectors;

@RestController
public class Vuln05CmdInjection {
    @GetMapping("/vuln05/ping")
    public String ping(@RequestParam String host) {
        try {
            // VULN:VULN-05:CWE-78:taint OS command injection — host concatenated into a shell command
            String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};
            Process p = Runtime.getRuntime().exec(cmd);
            String out = new BufferedReader(new InputStreamReader(p.getInputStream())).lines().collect(Collectors.joining("\n"));
            String err = new BufferedReader(new InputStreamReader(p.getErrorStream())).lines().collect(Collectors.joining("\n"));
            return out + "\n" + err;
        } catch (Exception e) { return "error: " + e; }
    }
}
