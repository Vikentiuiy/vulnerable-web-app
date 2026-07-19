package com.example.vulnapp.harness;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/** HARNESS (out of scan scope). Serves the landing page. */
@Controller
public class HomeController {
    @GetMapping("/")
    public String index() { return "index"; }
}
