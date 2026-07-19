package com.example.vulnapp.vulns

import org.springframework.web.bind.annotation.*


@RestController
class Vuln37Xpath {

    private val usersXml = "<users><user><name>admin</name><role>admin</role></user><user><name>alice</name><role>user</role></user></users>"
    @GetMapping("/vuln37/xlookup")
    fun xlookup(@RequestParam user: String): String = try {
        val xp = javax.xml.xpath.XPathFactory.newInstance().newXPath()
        // VULN:VULN-37:CWE-643:taint user input concatenated into an XPath expression
        val q = "/users/user[name='$user']/role"
        val nodes = xp.evaluate(q, org.xml.sax.InputSource(java.io.StringReader(usersXml)), javax.xml.xpath.XPathConstants.NODESET) as org.w3c.dom.NodeList
        (0 until nodes.length).joinToString(",") { nodes.item(it).textContent }
    } catch (e: Exception) { "error: $e" }
}
