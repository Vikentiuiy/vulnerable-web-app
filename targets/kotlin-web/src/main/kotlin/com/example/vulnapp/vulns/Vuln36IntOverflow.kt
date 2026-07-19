package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln36IntOverflow {

    @GetMapping("/vuln36/order")
    fun order(@RequestParam price: Int, @RequestParam qty: Int): String {
        // VULN:VULN-36:CWE-190:logic total computed in a 32-bit int; large values wrap around
        val total = price * qty
        return "{\"price\":$price,\"qty\":$qty,\"total\":$total}"
    }
}
