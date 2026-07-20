import Vapor
func registerVuln40(_ app: Application) {
    app.get("vuln40", "setsession") { req -> Response in
        let sid = (try? req.query.get(String.self, at: "sid")) ?? ""
        let resp = Response(status: .ok, body: .init(string: "{\"session\":\"\(sid)\"}"))
        // VULN:VULN-40:CWE-384:logic attacker-supplied session id adopted as-is (never rotated)
        resp.cookies["SESSIONID"] = HTTPCookies.Value(string: sid)
        return resp
    }
}
