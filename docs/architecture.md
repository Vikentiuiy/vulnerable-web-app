# Architecture

A deliberately insecure e-commerce-style web app ("VulnShop"). Three tiers, all
running in Docker so the vulnerabilities are actually reachable and exploitable.

```
 browser ──HTTP──> Spring Boot app (:8080) ──JDBC──> MySQL 8 (:3306)
   │                     │
   │                     ├── Thymeleaf views (server-rendered HTML)
   └── static JS (app.js, DOM sinks)
```

## Components

| Layer | Tech | Files |
|-------|------|-------|
| Frontend | HTML + vanilla JS | `src/main/resources/static/`, `templates/` |
| Backend | Java 17, Spring Boot 2.7 (Web, Thymeleaf, JDBC) | `src/main/java/com/example/vulnapp/` |
| Data | MySQL 8 | `db/init.sql` |
| Packaging | Docker + docker-compose | `Dockerfile`, `docker-compose.yml` |

## Backend map

| Controller | Route(s) | Planted vulns |
|-----------|----------|---------------|
| `HomeController` | `/` | (index) |
| `AuthController` | `POST /login` | VULN-02, 16, 17, 18, 30 |
| `SearchController` | `GET /search` | VULN-01, 03, 16 |
| `ProfileController` | `GET /profile`, `POST /profile/update` | VULN-01, 04, 11, 12 |
| `FileController` | `GET /files/download`, `POST /files/upload` | VULN-06, 07 |
| `AdminController` | `GET /admin/ping`, `GET /admin/fetch` | VULN-05, 10, 14, 15 |
| `ApiController` | `POST /api/deserialize`, `POST /api/xml`, `GET /api/redirect`, `GET /api/plugin`, `GET /api/encrypt` | VULN-08, 09, 22, 23, 24, 25 |
| `ExtraVulnsController` | `POST /api/register`, `GET /api/jwt/whoami`, `/api/eval`, `/api/export`, `/api/data`, `/api/order`, `/api/xlookup`, `/api/validate`, `/api/note`, `/api/setsession` | VULN-29, 31, 32, 33, 34, 36, 37, 38, 39, 40 |
| `StatusController` | `GET /dashboard`, `GET /api/status`, `POST /api/status/reset`, `POST /api/status/report` | live dashboard (not a vuln) |
| `util/CryptoUtil` | — | VULN-13, 14, 18, 22, 23 |
| `util/ExploitTracker` + `util/VulnCatalog` | — | runtime registry of which vulns have been exploited (drives the dashboard) |
| `util/Db` | — | JDBC helper exposing raw `Connection` for the SQLi sinks |

### Live exploitation dashboard

`/dashboard` renders the 40 vulnerabilities as status bars and polls `/api/status`
every 2s. The vulnerable sinks call `ExploitTracker.mark(id, evidence)` the instant
they act on clearly-malicious input, so any real attack (PoC script, curl, or the
dashboard's "Launch all exploits" button) flips a bar 🟢→🔴. Source/config-only
findings (weak crypto, hard-coded secrets, missing headers, the browser-executed
JS sinks) are confirmed client-side and posted to `/api/status/report`, which only
accepts that evidence-based subset — server-detectable vulns must be genuinely
exploited to light up.

## Data model

`users(id, username, password [md5], secret_answer [cleartext], role, bio, ssn)`
and `products(id, name, price, description)`. Seed users: `admin/admin123`,
`alice/password1`, `bob/qwerty`.

## Design notes

- SQL sinks use `Statement` + string concatenation (never `PreparedStatement`).
  Connections **are** closed (via try-with-resources) so the pool doesn't
  exhaust — the injection is in the query text, not a resource bug.
- `allowMultiQueries=true` on the JDBC URL enables stacked queries.
- Verbose error pages and `include-stacktrace=always` in
  `application.properties` make error-based extraction easy.
- The `/app/secret.txt` file exists purely as a traversal/XXE target.
