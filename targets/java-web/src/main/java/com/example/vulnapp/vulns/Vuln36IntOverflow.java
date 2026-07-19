package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln36IntOverflow {
    @GetMapping("/vuln36/order")
    public String order(@RequestParam int price, @RequestParam int qty) {
        // VULN:VULN-36:CWE-190:logic total computed in a 32-bit int; large values wrap around
        int total = price * qty;
        return "{\"price\":" + price + ",\"qty\":" + qty + ",\"total\":" + total + "}";
    }
}
