# sql-app — SQL injection with a live application taint source

A **thin Flask app in front of a real MySQL database** (schema + stored procedures).
Its whole purpose is to give SQL sinks a real **HTTP taint source**: user input flows
`request → query`, including the hard case where it flows **through a stored-procedure
call into dynamic SQL built inside the procedure**.

Why it exists: the standalone [`sql`](../sql) target scores **0** because pure `.sql`
has no taint source a SAST can latch onto. `sql-app` supplies one — and is the
cleanest place to prove whether an engine actually tracks SQL taint (spoiler in the
benchmark: PT AI does not; Semgrep does).

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | Python 3.11 |
| Web framework | **Flask** (one Blueprint per vuln, auto-registered) |
| WSGI server | **gunicorn** (2 workers so a self-SSRF/self-call doesn't deadlock) |
| DB driver | **mysql-connector-python** (`cursor.execute`, `cursor.callproc`) |
| Database | **MySQL 8** (official image), schema + stored procs from `db/` |

## Structure

```
app.py                 create app, auto-register vulns/ blueprints, install harness detector
store.py               MySQL connection helper (host from $DB_HOST, retry until healthy)
vulns/vulnNN_*.py      one Blueprint = one endpoint = one SQL sink (1:1)
harness/               catalog + tracker + after_request detector  (excluded from the scan)
db/01_schema.sql       insecure schema (unsalted MD5, cleartext secret, GRANT ALL) — config vulns
db/02_procs.sql        stored procedures with dynamic SQL (called by the app)
docker-compose.yml     two services: db (MySQL, healthcheck) + app (waits for db)
```

## The vulnerabilities (16)

**App-level SQL injection** — the same bug in every idiomatic form, so a miss is
undeniable:

- `VULN-81` string concatenation into `cursor.execute`
- `VULN-82` auth-bypass query (login)
- `VULN-83` **cross-boundary**: `cursor.callproc("search_products", [q])` — the app
  parameterises the call, but the injectable concatenation lives *inside* the
  procedure's dynamic SQL. Tests whether the engine follows taint across the app↔DB
  boundary.
- `VULN-84` f-string interpolation · `VULN-85` `str.format()`
- `VULN-86` ORDER BY (non-quotable context) · `VULN-88` numeric context (no quotes)
- `VULN-92` inside a `LIKE` pattern · `VULN-93` in an `UPDATE` · `VULN-94` in an `IN (…)` list

**Schema / config** (in `db/01_schema.sql`): `VULN-73` GRANT ALL, `VULN-74` unsalted
MD5 storage, `VULN-75` cleartext secret.

**Positive controls** — sinks PT AI's Python engine *does* detect, planted next to
the SQLi so the SQLi miss can't be blamed on the pipeline:

- `VULN-87` OS command injection (`subprocess.getoutput`)
- `VULN-89`/`VULN-90` **the combo** — one tainted `term` flows into a command sink
  (line 18, flagged) **and** a SQL sink (line 21, missed) in `vulns/vuln89_combo.py`.

See [`VULNERABILITIES.md`](VULNERABILITIES.md).

## Run it

```bash
docker compose up -d --build          # starts MySQL + the Flask app on :8085
python3 exploits/exploit_all.py       # "RESULT: 16/16 exploits succeeded"
docker compose down -v
```

Exploits fire the app over HTTP (UNION dumps, auth bypass, proc-mediated injection,
combo) and check the schema/config directly against the MySQL container.

## What the benchmark shows here

PT AI flags **both command-injection controls** but **misses all SQL injection**
(engine 25% = 2/8) — including the combo's SQL sink three lines below the flagged
command sink, on the same variable. Semgrep catches the SQLi (88%). Adding an app
taint source did **not** rescue PT AI's Python SQLi detection — it's a genuine
engine blind spot. See [`../../benchmark/README.md`](../../benchmark/README.md).
