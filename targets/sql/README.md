# sql — standalone SQL (schema + stored procedures)

Pure **SQL** weaknesses: an insecure MySQL schema and stored procedures that build
**dynamic SQL by string concatenation**. No application layer — this target measures
what a SAST does with SQL *alone*.

## Technologies

| Piece | Choice |
|-------|--------|
| Database | **MySQL 8** (official image) |
| Content | DDL + seed + stored procedures (`db/*.sql`) run at container init |
| Exploit driver | Python 3 via `docker exec … mysql -e "CALL …"` |

## Structure

```
db/01_schema.sql       tables + seed + GRANT ALL  (unsalted MD5, cleartext secret, excessive privileges)
db/02_procs.sql        stored procedures: search/auth by concatenated dynamic SQL, definer-rights report,
                       dynamic table-name query
docker-compose.yml     MySQL with db/ mounted as /docker-entrypoint-initdb.d
```

## Vulnerabilities (7)

Stored-procedure SQL injection (`VULN-71/72/78`), `SQL SECURITY DEFINER` privilege
escalation (`VULN-76`), excessive `GRANT ALL` (`VULN-73`), unsalted (`VULN-74`) and
cleartext (`VULN-75`) storage. See [`VULNERABILITIES.md`](VULNERABILITIES.md).

## Run it

```bash
docker compose up -d                  # MySQL on :3307, schema+procs auto-loaded
python3 exploits/exploit_all.py       # "RESULT: 7/7 exploits succeeded" (CALL/SELECT via docker exec)
docker compose down -v
```

## Benchmark note

PT AI returns **0** across all profiles — pure `.sql` has no recognised taint source,
so stored-procedure SQLi and schema/config weaknesses aren't flagged. SQL injection
is detected via **application-language** taint instead; see the companion
[`sql-app`](../sql-app) target, which adds a live HTTP source (and shows PT AI still
misses the SQLi). See [`../../benchmark/README.md`](../../benchmark/README.md).
