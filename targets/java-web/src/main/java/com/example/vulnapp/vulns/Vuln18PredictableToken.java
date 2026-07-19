package com.example.vulnapp.vulns;

import com.example.vulnapp.vulns.crypto.Secrets;
import org.springframework.web.bind.annotation.*;

@RestController
public class Vuln18PredictableToken {
    @GetMapping("/vuln18/token")
    public String token(@RequestParam String user) {
        // predictable-token sink lives in Secrets.weakToken (VULN-18); seeded from username
        return Secrets.weakToken(user.hashCode());
    }
}
