import Vapor
private var v04store = [String: String]()
func registerVuln04(_ app: Application) {
    app.get("vuln04", "save") { req -> String in
        let id = (try? req.query.get(String.self, at: "id")) ?? ""
        v04store[id] = (try? req.query.get(String.self, at: "bio")) ?? ""
        return "{\"status\":\"saved\"}"
    }
    app.get("vuln04", "show") { req -> Response in
        let id = (try? req.query.get(String.self, at: "id")) ?? ""
        let bio = v04store[id] ?? ""
        // VULN:VULN-04:CWE-79:taint stored XSS: persisted bio rendered into HTML unescaped
        return Response(status: .ok, headers: ["Content-Type": "text/html"], body: .init(string: "<html><body><div>\(bio)</div></body></html>"))
    }
}
