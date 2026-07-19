package com.example.vulnapp.harness

import org.springframework.web.bind.annotation.*

/** HARNESS (out of scan scope). Status JSON for the exploitation dashboard. */
@RestController
class StatusController(private val tracker: ExploitTracker) {
    @GetMapping("/api/status")
    fun status(): Map<String, Any?> = mapOf(
        "total" to tracker.total(), "exploited" to tracker.exploitedCount(), "items" to tracker.snapshot())

    @PostMapping("/api/status/reset")
    fun reset(): Map<String, Any?> { tracker.reset(); return mapOf("status" to "reset") }
}
