import Vapor

func registerVuln33(_ app: Application) {
    app.get("vuln33", "export") { req -> Response in
        let note = req.query[String.self, at: "note"] ?? ""
        // VULN:VULN-33:CWE-1236:taint user data written into CSV without neutralising formulas
        return Response(status: .ok, headers: ["Content-Type": "text/csv"], body: .init(string: "id,note\n1,\(note)\n"))
    }
}
