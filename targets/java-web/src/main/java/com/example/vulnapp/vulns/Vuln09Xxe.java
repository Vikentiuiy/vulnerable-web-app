package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import javax.xml.parsers.*;
import java.io.ByteArrayInputStream;
import org.w3c.dom.Document;

@RestController
public class Vuln09Xxe {
    @PostMapping(value = "/vuln09/xml", consumes = "application/xml")
    public String xml(@RequestBody String body) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // VULN:VULN-09:CWE-611:taint XXE — external entity processing left enabled
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body.getBytes("UTF-8")));
            doc.getDocumentElement().normalize();
            return "root=" + doc.getDocumentElement().getNodeName() + ", text=" + doc.getDocumentElement().getTextContent();
        } catch (Exception e) { return "error: " + e; }
    }
}
