import Vapor
func registerVuln29(_ app: Application) {
    app.get("vuln29", "register") { req -> [String: String] in
        let user = (try? req.query.get(String.self, at: "username")) ?? ""
        let role = (try? req.query.get(String.self, at: "role")) ?? "user"
        // VULN:VULN-29:CWE-915:logic caller-controlled role bound directly (privilege escalation)
        return ["status": "registered", "username": user, "role": role]
    }
}
