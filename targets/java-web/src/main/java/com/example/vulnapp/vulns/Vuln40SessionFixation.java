package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@RestController
public class Vuln40SessionFixation {
    @GetMapping("/vuln40/setsession")
    public String setSession(@RequestParam String sid, HttpServletResponse response) {
        // VULN:VULN-40:CWE-384:logic session id taken from the request and set as-is (never rotated)
        Cookie c = new Cookie("JSESSIONID", sid);
        c.setPath("/");
        response.addCookie(c);
        return "{\"session\":\"" + sid + "\"}";
    }
}
