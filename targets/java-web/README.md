# java-web — Java / Spring Boot reference target

The **reference target** ("VulnShop") and the richest of the set: a Spring Boot app
spanning **Java + SQL + browser JavaScript**, exploited over HTTP against a real
**MySQL** database. It defines the 1:1 contract the other targets follow.

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | Java 17 |
| Framework | **Spring Boot 2.7** (`spring-boot-starter-web`, `-thymeleaf`, `-jdbc`) |
| Build | **Maven** (`spring-boot-maven-plugin`) |
| Database | **MySQL 8** (`mysql-connector-java`), schema in `db/init.sql` |
| Notable dep | `commons-collections4:4.0` — a classic deserialization gadget (also an SCA finding) |
| Frontend | Thymeleaf templates + vanilla JS (`static/js/app.js` — DOM sinks) |
| Base image | `maven:3.9-eclipse-temurin-17` (build) → `eclipse-temurin:17-jre` (run) |

## Structure

```
src/main/java/com/example/vulnapp/
  VulnAppApplication.java   Spring Boot entry point
  infra/Db.java             raw JDBC connection helper (for the string-concat SQLi sinks)
  vulns/VulnNN*.java        one @RestController = one endpoint = one sink (1:1, 40 vulns)
  vulns/crypto/*.java       WeakHash (MD5), AesCipher (static IV + hard-coded key), Secrets (token)
  harness/                  tracker, catalog, StatusController, ExploitDetectionFilter (excluded from scan)
src/main/resources/
  templates/                Thymeleaf views  ·  static/js/app.js  (DOM XSS, hard-coded key, eval)
  application.properties    insecure config (verbose errors, no X-Frame-Options)
db/init.sql                 insecure schema (unsalted MD5, cleartext secret, GRANT ALL)
```

All runtime instrumentation lives in a single `ExploitDetectionFilter` (servlet
`Filter`) under `harness/`, excluded via `scope.txt`, so the scanned sink files
contain only the vulnerability.

## Run it

```bash
docker compose up -d --build          # app on :8080, MySQL on :3306
python3 exploits/exploit_all.py       # "RESULT: 40/40 exploits succeeded"
docker compose down -v
```

Live status: `http://localhost:8080/api/status` (each planted vuln flips as it is
exploited). Full table in [`VULNERABILITIES.md`](VULNERABILITIES.md).

## Benchmark note

The strongest engine result of the set — PT AI **61%** taint-recall (SQLi, OS
command, path traversal, SSRF, XXE, deserialization, unsafe reflection, XPath, log
injection). Its notable engine gaps here are **XSS** (reflected/stored/DOM) and open
redirect. See [`../../benchmark/README.md`](../../benchmark/README.md).
