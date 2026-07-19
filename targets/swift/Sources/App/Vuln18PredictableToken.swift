import Vapor
import Foundation

func registerVuln18(_ app: Application) {
    app.get("vuln18", "token") { req -> String in
        let user = req.query[String.self, at: "user"] ?? ""
        // VULN:VULN-18:CWE-330:pattern predictable token derived deterministically from the username
        var seed = UInt64(abs(user.hashValue))
        var out = ""
        for _ in 0..<16 { seed = seed &* 6364136223846793005 &+ 1; out += String(format: "%x", (seed >> 33) & 0xF) }
        return out
    }
}
