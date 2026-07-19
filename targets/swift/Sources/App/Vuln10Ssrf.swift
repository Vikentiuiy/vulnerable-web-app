import Vapor
import Foundation

func registerVuln10(_ app: Application) {
    app.get("vuln10", "fetch") { req async throws -> String in
        let url = req.query[String.self, at: "url"] ?? ""
        // VULN:VULN-10:CWE-918:taint SSRF — server fetches an arbitrary user-supplied URL
        let resp = try await req.client.get(URI(string: url))
        return resp.body.map { String(buffer: $0) } ?? ""
    }
}
