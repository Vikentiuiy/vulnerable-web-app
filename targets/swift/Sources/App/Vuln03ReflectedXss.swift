import Vapor

func registerVuln03(_ app: Application) {
    app.get("vuln03", "echo") { req -> Response in
        let q = req.query[String.self, at: "q"] ?? ""
        // VULN:VULN-03:CWE-79:taint reflected XSS: input echoed into HTML unescaped
        let html = "<html><body><h3>You searched for: \(q)</h3></body></html>"
        return Response(status: .ok, headers: ["Content-Type": "text/html"], body: .init(string: html))
    }
}
