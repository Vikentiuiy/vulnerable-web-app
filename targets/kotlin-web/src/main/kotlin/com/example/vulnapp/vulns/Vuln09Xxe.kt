package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln09Xxe {

    @PostMapping("/vuln09/xml", consumes = ["application/xml"])
    fun xml(@RequestBody body: String): String = try {
        val dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        // VULN:VULN-09:CWE-611:taint XXE — external entity processing left enabled
        val doc = dbf.newDocumentBuilder().parse(java.io.ByteArrayInputStream(body.toByteArray(Charsets.UTF_8)))
        "root=" + doc.documentElement.nodeName + ", text=" + doc.documentElement.textContent
    } catch (e: Exception) { "error: $e" }
}
