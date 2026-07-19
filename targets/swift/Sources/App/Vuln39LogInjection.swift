import Vapor

func registerVuln39(_ app: Application) {
    app.get("vuln39", "note") { req -> String in
        let text = req.query[String.self, at: "text"] ?? ""
        // VULN:VULN-39:CWE-117:taint user input logged without neutralising CR/LF
        req.logger.warning("[audit] user note: \(text)")
        return "{\"logged\":true}"
    }
}
