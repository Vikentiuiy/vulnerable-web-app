# swift — Swift / Vapor target

A vulnerable **Swift** web app built on the **Vapor** framework, exploited over HTTP.

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | Swift 5.9 |
| Framework | **Vapor 4** (async routes) |
| Crypto | **swift-crypto** (`Insecure.MD5`) — bundled with Vapor |
| Build | Swift Package Manager (`swift build -c release`) |
| Base image | `swift:5.9-jammy` (build) → `swift:5.9-jammy-slim` (run) |

## Structure

```
Package.swift                 Vapor dependency
Sources/App/main.swift        Application setup, route registration, VULN-35 (no X-Frame-Options)
Sources/App/VulnNN*.swift     one `func registerVulnNN(_ app:)` = one route = one sink (1:1)
Dockerfile                    SwiftPM build (static stdlib) → slim runtime
```

## Run it

```bash
docker compose up -d --build          # app on :8084  (first build is slow — Swift image + SPM)
python3 exploits/exploit_all.py       # "RESULT: 20/20 exploits succeeded"
docker compose down
```

20 vulns: OS command injection (`Process`), path traversal, SSRF (Vapor client),
reflected XSS, open redirect, weak MD5, insecure cookie, predictable token, CSV
injection, CORS, ReDoS (`NSRegularExpression`), log injection, clickjacking. See
[`VULNERABILITIES.md`](VULNERABILITIES.md).

## Benchmark note

PT AI produces **0 findings** for Swift across all profiles (files upload, but the
engine flags nothing) — effectively no working Swift analysis on this stand. See
[`../../benchmark/README.md`](../../benchmark/README.md).
