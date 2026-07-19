import Vapor
import Foundation

func registerVuln17(_ app: Application) {
    app.get("vuln17", "login") { req -> Response in
        let user = req.query[String.self, at: "user"] ?? "guest"
        let token = String(format: "%016x", abs(user.hashValue))
        let resp = Response(status: .ok, body: .init(string: "{\"token\":\"\(token)\"}"))
        // VULN:VULN-17:CWE-614:config auth cookie set without HttpOnly/Secure flags
        resp.cookies["auth"] = HTTPCookies.Value(string: token, isSecure: false, isHTTPOnly: false)
        return resp
    }
}
