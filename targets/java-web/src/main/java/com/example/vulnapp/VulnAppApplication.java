package com.example.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Intentionally vulnerable web application for SAST benchmarking and hands-on
 * exploitation practice. Every "VULN:VULN-xx:CWE-nnn" comment marks a planted,
 * exploitable weakness. DO NOT DEPLOY THIS ANYWHERE REACHABLE.
 */
@SpringBootApplication
public class VulnAppApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnAppApplication.class, args);
    }
}
