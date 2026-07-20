import Vapor
func registerVuln45(_ app: Application) {
    app.get("vuln45", "lang") { req -> Response in
        let lang = (try? req.query.get(String.self, at: "lang")) ?? "en"
        let resp = Response(status: .ok, body: .init(string: "{\"lang\":\"set\"}"))
        // VULN:VULN-45:CWE-113:taint untrusted input reflected into a response header
        resp.headers.replaceOrAdd(name: "Content-Language", value: lang)
        return resp
    }
}
