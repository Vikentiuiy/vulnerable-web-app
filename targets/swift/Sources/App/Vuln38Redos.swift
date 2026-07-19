import Vapor
import Foundation

func registerVuln38(_ app: Application) {
    app.get("vuln38", "validate") { req -> String in
        let email = String((req.query[String.self, at: "email"] ?? "").prefix(30))
        // VULN:VULN-38:CWE-1333:logic catastrophically-backtracking regex applied to user input
        let regex = try NSRegularExpression(pattern: "^(.*a){12}$")
        let range = NSRange(email.startIndex..., in: email)
        let match = regex.firstMatch(in: email, range: range) != nil
        return "{\"valid\":\(match)}"
    }
}
