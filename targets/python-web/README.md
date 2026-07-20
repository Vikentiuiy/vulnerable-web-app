# python-web — Python / Flask target

A vulnerable **Flask** app exploited over HTTP, backed by a self-contained
**SQLite** file. Includes Python-specific sinks (SSTI, pickle, unsafe YAML, `eval`)
and a rich set of XSS variants used to prove PT AI's XSS blind spot.

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | Python 3.11 |
| Framework | **Flask** (one Blueprint per vuln, auto-registered from `vulns/`) |
| WSGI server | **gunicorn** (2 workers + threads) |
| Database | **SQLite** (`sqlite3`, seeded at startup) |
| Libraries | `lxml` (XXE / XPath), `PyYAML` (unsafe load), `requests` (SSRF), Jinja2 via Flask (SSTI) |
| Base image | `python:3.11-slim` |

## Structure

```
app.py                 create app, seed SQLite (unsalted MD5, cleartext secret), register blueprints
store.py               SQLite connection helper
vulns/vulnNN_*.py      one Blueprint = one endpoint = one sink (1:1)
harness/               catalog + tracker + after_request detector  (excluded from the scan)
```

## Vulnerability highlights (33)

Classic web sinks plus Python-idiomatic ones: **SSTI** (`render_template_string`),
**pickle** deserialization, **unsafe `yaml.load`**, **`eval`** code injection,
**XPath**/**XXE** via `lxml`, and reflected/stored/attribute/JS-context **XSS**
(including a combo where a command sink is flagged but the XSS beside it is missed).
See [`VULNERABILITIES.md`](VULNERABILITIES.md).

## Run it

```bash
docker compose up -d --build          # app on :8082
python3 exploits/exploit_all.py       # "RESULT: 33/33 exploits succeeded"
docker compose down
```

## Benchmark note

PT AI's engine gets **40%** here and catches SSRF, pickle/YAML deserialization,
`eval`, command injection and path traversal — but **misses Python SQL injection
and all XSS** (proven with positive controls). Semgrep catches those (85%), so the
two engines are complementary. See [`../../benchmark/README.md`](../../benchmark/README.md).
