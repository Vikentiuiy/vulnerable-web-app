import Vapor
import Crypto
import Foundation
func registerVuln22(_ app: Application) {
    app.get("vuln22", "encrypt") { req -> String in
        let data = (try? req.query.get(String.self, at: "data")) ?? ""
        // VULN:VULN-22:CWE-329:pattern hard-coded key + fixed nonce -> deterministic AES-GCM
        let key = SymmetricKey(data: Data("0123456789abcdef".utf8))
        let nonce = try AES.GCM.Nonce(data: Data("fixednonce12".utf8))
        let sealed = try AES.GCM.seal(Data(data.utf8), using: key, nonce: nonce)
        return sealed.ciphertext.base64EncodedString()
    }
}
