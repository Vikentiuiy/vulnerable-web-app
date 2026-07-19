package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln08Deserialize {

    @PostMapping("/vuln08/deserialize")
    fun deserialize(@RequestBody b64: String): String = try {
        val raw = java.util.Base64.getDecoder().decode(b64.trim())
        // VULN:VULN-08:CWE-502:taint deserialization of untrusted data
        val obj = java.io.ObjectInputStream(java.io.ByteArrayInputStream(raw)).readObject()
        "deserialized: " + obj.javaClass.name
    } catch (e: Exception) { "error: $e" }
}
