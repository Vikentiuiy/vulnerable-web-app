# kotlin-web — Kotlin / Spring Boot target

A vulnerable web app written in **Kotlin**, exploited over HTTP. Self-contained: an
in-memory **H2** database seeded at startup, so there is no separate DB container.

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | Kotlin 1.9 (JVM 17) |
| Framework | **Spring Boot 2.7** (`spring-boot-starter-web`, `-jdbc`) |
| Build | **Gradle** (Kotlin DSL), `bootJar` |
| Database | **H2** in-memory (`jdbc:h2:mem:`), seeded via `CommandLineRunner` |
| Base image | `gradle:8.5-jdk17` (build) → `eclipse-temurin:17-jre` (run) |

## Structure

```
src/main/kotlin/com/example/vulnapp/
  VulnApp.kt              @SpringBootApplication + H2 schema/seed (unsalted MD5, cleartext secret)
  infra/Db.kt             raw JDBC connection helper (for the string-concat SQLi sinks)
  vulns/VulnNN*.kt        one @RestController = one endpoint = one sink (1:1)
  vulns/crypto/*.kt       WeakHash (MD5), AesCipher (static IV + hard-coded key), Secrets (token)
  harness/                tracker, catalog, StatusController, ExploitDetectionFilter (excluded from scan)
build.gradle.kts          Spring Boot + Kotlin plugins
```

Instrumentation is a single `ExploitDetectionFilter` (a servlet `Filter`) in
`harness/`, excluded via `scope.txt` — the vuln controllers stay clean.

## Run it

```bash
docker compose up -d --build          # app on :8081
python3 exploits/exploit_all.py       # "RESULT: 31/31 exploits succeeded"
docker compose down
```

31 vulns across taint / pattern / config / logic — see [`VULNERABILITIES.md`](VULNERABILITIES.md).

## Benchmark note

PT AI's engine gets **33%** taint-recall here — it catches SQLi, OS command, XPath
and unsafe reflection, but loses path traversal, SSRF, deserialization, XXE and log
injection that it catches in Java. Semgrep has essentially **no Kotlin taint
analysis** (0%), so this is PT-AI-only territory.
