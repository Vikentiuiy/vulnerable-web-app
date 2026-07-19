import Vapor
import Crypto
import Foundation

func registerVuln13(_ app: Application) {
    app.get("vuln13", "hash") { req -> String in
        let p = req.query[String.self, at: "p"] ?? ""
        // VULN:VULN-13:CWE-327:pattern broken/weak hash (MD5) used for passwords
        let digest = Insecure.MD5.hash(data: Data(p.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
