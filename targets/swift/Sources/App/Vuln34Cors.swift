import Vapor

func registerVuln34(_ app: Application) {
    app.get("vuln34", "data") { req -> Response in
        let resp = Response(status: .ok, body: .init(string: "{\"secret\":\"account-balance-42000\"}"))
        if let origin = req.headers.first(name: "Origin") {
            // VULN:VULN-34:CWE-942:config arbitrary Origin reflected + credentials allowed
            resp.headers.replaceOrAdd(name: "Access-Control-Allow-Origin", value: origin)
            resp.headers.replaceOrAdd(name: "Access-Control-Allow-Credentials", value: "true")
        }
        return resp
    }
}
