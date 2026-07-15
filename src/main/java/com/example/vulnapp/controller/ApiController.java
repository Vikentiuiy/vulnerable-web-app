package com.example.vulnapp.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.URI;
import java.util.Base64;

import org.w3c.dom.Document;

/**
 * Misc API endpoints: deserialization, XML parsing, redirect, reflection.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    /**
     * Accept a base64-encoded Java serialized object and deserialize it.
     * With commons-collections4 on the classpath this is a classic RCE gadget sink.
     */
    @PostMapping("/deserialize")
    public String deserialize(@RequestBody String base64) {
        try {
            byte[] raw = Base64.getDecoder().decode(base64.trim());
            // VULN:VULN-08:CWE-502 deserialization of untrusted data (RCE via gadget chains)
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw));
            Object obj = ois.readObject();
            return "deserialized: " + obj;
        } catch (Exception e) {
            return "error: " + e;
        }
    }

    /**
     * Parse an XML document supplied by the caller. External entities are left
     * enabled, so this is an XXE sink (file read / SSRF via entities).
     */
    @PostMapping(value = "/xml", consumes = "application/xml")
    public String xml(@RequestBody String body) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // VULN:VULN-09:CWE-611 XXE — external entity processing left enabled
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body.getBytes("UTF-8")));
            doc.getDocumentElement().normalize();
            return "root=" + doc.getDocumentElement().getNodeName()
                    + ", text=" + doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "error: " + e;
        }
    }

    /**
     * Redirect helper. The target comes straight from the query string with no
     * validation against an allow-list.
     */
    @GetMapping("/redirect")
    public ResponseEntity<Void> redirect(@RequestParam("url") String url) {
        // VULN:VULN-24:CWE-601 open redirect — unvalidated redirect target
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    /**
     * "Plugin loader" — instantiate a class chosen by the caller. Arbitrary class
     * instantiation from user input.
     */
    @GetMapping("/plugin")
    public String plugin(@RequestParam("class") String className) {
        try {
            // VULN:VULN-25:CWE-470 unsafe reflection — class name controlled by the user
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            return "loaded: " + instance.getClass().getName();
        } catch (Exception e) {
            return "error: " + e;
        }
    }
}
