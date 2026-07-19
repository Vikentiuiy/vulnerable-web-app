import Vapor
import Foundation

func registerVuln05(_ app: Application) {
    app.get("vuln05", "ping") { req -> String in
        let host = req.query[String.self, at: "host"] ?? ""
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        // VULN:VULN-05:CWE-78:taint OS command injection — host concatenated into a shell command
        task.arguments = ["-c", "ping -c 1 \(host)"]
        let pipe = Pipe(); task.standardOutput = pipe; task.standardError = pipe
        try task.run(); task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
