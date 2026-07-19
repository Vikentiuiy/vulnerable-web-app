package com.example.vulnapp.vulns;

import com.example.vulnapp.vulns.crypto.Secrets;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

@RestController
public class Vuln17InsecureCookie {
    @PostMapping("/vuln17/login")
    public Map<String,Object> login(@RequestParam String username, HttpServletResponse response) {
        String token = Secrets.weakToken(username.hashCode());
        // VULN:VULN-17:CWE-614:config auth cookie set without HttpOnly/Secure flags
        Cookie c = new Cookie("auth", token);
        c.setPath("/");
        response.addCookie(c);
        Map<String,Object> out = new HashMap<>();
        out.put("status","ok"); out.put("token", token);
        return out;
    }
}
