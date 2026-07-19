import Vapor

func registerVuln24(_ app: Application) {
    app.get("vuln24", "redirect") { req -> Response in
        let url = req.query[String.self, at: "url"] ?? ""
        // VULN:VULN-24:CWE-601:taint open redirect — unvalidated redirect target
        return req.redirect(to: url)
    }
}
