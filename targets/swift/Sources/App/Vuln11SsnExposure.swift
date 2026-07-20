import Vapor
func registerVuln11(_ app: Application) {
    app.get("vuln11", "profile") { req -> [String: String] in
        let id = (try? req.query.get(String.self, at: "id")) ?? "1"
        // VULN:VULN-11:CWE-200:logic sensitive data (SSN) returned to any caller
        return ["id": id, "username": "admin", "ssn": "111-22-3333"]
    }
}
