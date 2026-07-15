package com.example.vulnapp.controller;

import com.example.vulnapp.util.ExploitTracker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Live exploitation dashboard: status JSON + the /dashboard page.
 */
@Controller
public class StatusController {

    private final ExploitTracker tracker;

    @Autowired
    public StatusController(ExploitTracker tracker) {
        this.tracker = tracker;
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/api/status")
    @ResponseBody
    public Map<String, Object> status() {
        Map<String, Object> out = new HashMap<>();
        List<Map<String, Object>> items = tracker.snapshot();
        out.put("total", tracker.total());
        out.put("exploited", tracker.exploitedCount());
        out.put("items", items);
        return out;
    }

    @PostMapping("/api/status/reset")
    @ResponseBody
    public Map<String, Object> reset() {
        tracker.reset();
        Map<String, Object> out = new HashMap<>();
        out.put("status", "reset");
        return out;
    }

    /**
     * Client-confirmed evidence for the source/config vulnerabilities that have
     * no server-side sink to trip (crypto/secret/header checks and the two
     * browser-executed JS sinks). The dashboard gathers the evidence and posts
     * it here. Restricted to that subset so server-detectable vulns can only be
     * lit up by actually exploiting them.
     */
    @PostMapping("/api/status/report")
    @ResponseBody
    public Map<String, Object> report(@RequestParam String id, @RequestParam(defaultValue = "") String detail) {
        Map<String, Object> out = new HashMap<>();
        java.util.Set<String> allowed = java.util.Set.of(
            "VULN-13", "VULN-17", "VULN-18", "VULN-19", "VULN-20", "VULN-21",
            "VULN-26", "VULN-27", "VULN-28", "VULN-35");
        if (!allowed.contains(id)) {
            out.put("status", "rejected");
            out.put("reason", "id must be exploited via its real sink, not self-reported");
            return out;
        }
        tracker.mark(id, detail);
        out.put("status", "ok");
        return out;
    }
}
