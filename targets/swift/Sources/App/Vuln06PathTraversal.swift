import Vapor
import Foundation

func registerVuln06(_ app: Application) {
    app.get("vuln06", "download") { req -> String in
        let name = req.query[String.self, at: "name"] ?? ""
        // VULN:VULN-06:CWE-22:taint path traversal — user input concatenated into a filesystem path
        return try String(contentsOfFile: "/app/data/\(name)", encoding: .utf8)
    }
}
