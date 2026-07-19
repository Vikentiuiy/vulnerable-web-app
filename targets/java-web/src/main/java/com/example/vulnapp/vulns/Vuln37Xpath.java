package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import org.w3c.dom.NodeList;

@RestController
public class Vuln37Xpath {
    private static final String USERS_XML =
        "<users><user><name>admin</name><role>admin</role></user>" +
        "<user><name>alice</name><role>user</role></user></users>";

    @GetMapping("/vuln37/xlookup")
    public String xlookup(@RequestParam String user) {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            // VULN:VULN-37:CWE-643:taint user input concatenated into an XPath expression
            String query = "/users/user[name='" + user + "']/role";
            NodeList nodes = (NodeList) xpath.evaluate(query, new InputSource(new java.io.StringReader(USERS_XML)), XPathConstants.NODESET);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < nodes.getLength(); i++) sb.append(nodes.item(i).getTextContent()).append(",");
            return "roles: " + sb;
        } catch (Exception e) { return "error: " + e; }
    }
}
