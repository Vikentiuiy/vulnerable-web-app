import Vapor
import Foundation

let app = try Application(.detect())
defer { app.shutdown() }

// VULN:VULN-35:CWE-1021:config no X-Frame-Options / CSP frame-ancestors middleware added -> clickjacking
app.get { _ in "vuln-swift-web" }

registerVuln03(app)
registerVuln04(app)
registerVuln05(app)
registerVuln06(app)
registerVuln10(app)
registerVuln11(app)
registerVuln13(app)
registerVuln16(app)
registerVuln17(app)
registerVuln18(app)
registerVuln22(app)
registerVuln24(app)
registerVuln29(app)
registerVuln33(app)
registerVuln34(app)
registerVuln38(app)
registerVuln39(app)
registerVuln40(app)
registerVuln45(app)

try app.run()
