import Vapor
func registerVuln16(_ app: Application) {
    app.get("vuln16", "lookup") { req -> String in
        let id = (try? req.query.get(String.self, at: "id")) ?? ""
        guard Int(id) != nil else {
            // VULN:VULN-16:CWE-209:logic internal error + query detail returned to the client
            return "error: invalid id '\(id)' — internal query was: SELECT * FROM users WHERE id = \(id)"
        }
        return "{\"id\":\(id)}"
    }
}
