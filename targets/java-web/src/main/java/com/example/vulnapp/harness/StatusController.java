package com.example.vulnapp.harness;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * HARNESS (out of scan scope). Live exploitation dashboard: status JSON + the
 * /dashboard page. Server-detectable vulns are lit up only by real attacks via
 * {@link ExploitDetectionFilter}; the browser-only sinks (DOM XSS, JS secret,
 * client eval) post client-confirmed evidence here.
 */
@Controller
public class StatusController {

    private final ExploitTracker tracker;

    @Autowired
    public StatusController(ExploitTracker tracker) { this.tracker = tracker; }

    @GetMapping("/dashboard")
    public String dashboard() { return "dashboard"; }

    @GetMapping("/api/status")
    @ResponseBody
    public Map<String, Object> status() {
        Map<String, Object> out = new HashMap<>();
        out.put("total", tracker.total());
        out.put("exploited", tracker.exploitedCount());
        out.put("items", tracker.snapshot());
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

    /** Client-confirmed evidence for browser-only sinks (no server sink to trip). */
    @PostMapping("/api/status/report")
    @ResponseBody
    public Map<String, Object> report(@RequestParam String id, @RequestParam(defaultValue = "") String detail) {
        Map<String, Object> out = new HashMap<>();
        java.util.Set<String> allowed = java.util.Set.of("VULN-26", "VULN-27", "VULN-28", "VULN-35");
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
