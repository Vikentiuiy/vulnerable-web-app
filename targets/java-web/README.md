# vulnerable-web-app

> ⚠️ **Intentionally vulnerable.** A runnable Java + JavaScript + SQL web app
> ("VulnShop") with **40 planted, exploitable vulnerabilities** (52 sink
> locations). Built for benchmarking SAST tools and hands-on exploitation
> practice. **DO NOT DEPLOY** anywhere reachable from an untrusted network.

Unlike a pile of static bad-code snippets, this app actually **builds, runs, and
is exploitable end-to-end** in Docker — every finding in the reference SARIF has
a working proof-of-concept.

## What's in the box

| Path | What |
|------|------|
| `src/`, `db/` | The vulnerable app (Spring Boot backend, JS frontend, MySQL schema) |
| `Dockerfile`, `docker-compose.yml` | Build + run the whole stack |
| `VULNERABILITIES.md` | The list of all 40 planted vulns (CWE, location, entry point) |
| `docs/` | Architecture + copy-paste exploitation guide |
| `poc/` | `exploit_all.py` — automated end-to-end exploits (proves they fire) |
| `checker/` | `build_reference.py` (ground truth) + `sast_checker.py` (scorer) + `reference.sarif` |
| `/dashboard` | Live exploitation dashboard — status bars flip 🟢→🔴 as each vuln is exploited |

Languages: **Java** (Spring Boot sinks), **SQL** (insecure schema/storage/privs),
**JavaScript** (DOM XSS, secret leakage, `eval`).

## 1. Build & run (Docker)

```bash
docker compose up -d --build
# app  -> http://localhost:8080
# mysql-> localhost:3306 (vulnapp / root:root)
```

Wait ~15s for MySQL to become healthy and the app to boot, then open
<http://localhost:8080>. Tear down with `docker compose down -v`.

Seed users: `admin/admin123`, `alice/password1`, `bob/qwerty`.

## 2. Prove the vulns are exploitable (POC)

The PoC suite needs Python 3 and the `requests` package. Use an isolated
virtual environment (venv) so nothing touches your system Python:

```bash
# create & activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# install dependencies into the venv
pip install --upgrade pip
pip install -r poc/requirements.txt

# run the exploits
python3 poc/exploit_all.py                 # runs every exploit, prints PASS/FAIL
python3 poc/exploit_all.py --only sqli,xxe # subset

deactivate                          # leave the venv when done
```

Or the one-liner wrapper (creates deps and runs): `bash poc/run_all.sh`.

Expected: `RESULT: 40/40 exploits succeeded`. See `docs/exploitation-guide.md`
for the `curl` version of each, and open the live **dashboard** at
<http://localhost:8080/dashboard> to watch each vulnerability's status bar flip
from 🟢 green (not exploited) to 🔴 red (exploited) in real time.

## 3. Benchmark a SAST tool

The ground-truth SARIF is generated straight from `VULN:VULN-x:CWE-n` markers in
the source, so line numbers always match the code:

```bash
python3 checker/build_reference.py         # (re)build checker/reference.sarif — 52 findings
```

Run your SAST tool (Semgrep, CodeQL, SpotBugs/find-sec-bugs, PT AI, Snyk, …),
export **SARIF**, then compare:

```bash
# Location-based (default): same file, line within ±tolerance of the planted sink
python3 checker/sast_checker.py -r checker/reference.sarif -a tool_output.sarif

# Also require the CWE class to match
python3 checker/sast_checker.py -r checker/reference.sarif -a tool_output.sarif --require-cwe

# Coarser: match purely by CWE class (ignores location)
python3 checker/sast_checker.py -r checker/reference.sarif -a tool_output.sarif --match cwe

# CI gate: fail if recall < 60%
python3 checker/sast_checker.py -r checker/reference.sarif -a tool_output.sarif --fail-under 60
```

You get **matched / missed / extra** findings plus **recall / precision / F1**.
The checker maps tool-specific rule names to CWEs (e.g. PT Application Inspector's
"SQL Injection" → CWE-89), so it works even when a tool doesn't emit CWE ids.

## Live exploitation dashboard

Open <http://localhost:8080/dashboard>. Each of the 40 vulnerabilities has a
status bar — 🟢 **green = not exploited**, 🔴 **red = exploited/confirmed**, with
the concrete evidence next to it (leaked SSN, cracked MD5, ReDoS timing, the
overflowed total, …). The bars flip to red when the vuln is actually attacked —
by the PoC script, by `curl`, or by the dashboard's own **“Launch all exploits”**
button, which fires a benign exploit at every endpoint from the browser. Server
sinks self-report on real attacks, so the board can't be faked green→red.

## Vulnerability classes (40)

SQLi (×2), reflected + stored + DOM XSS, OS command injection, path traversal,
unrestricted upload, insecure deserialization, XXE, SSRF, open redirect, unsafe
reflection, IDOR, sensitive-data exposure, missing authentication, verbose
errors, insecure/predictable session cookies, weak crypto (MD5, hard-coded AES
key, static IV), hard-coded secrets (server + JS), insecure SQL schema (unsalted
passwords, cleartext storage, excessive privileges), client-side `eval`,
mass assignment, no rate limiting, JWT-alg-none, SpEL/EL injection, CSV/formula
injection, insecure CORS, clickjacking, integer overflow, XPath injection,
ReDoS, log injection, session fixation.

Full table with CWE ids and locations: **[`VULNERABILITIES.md`](VULNERABILITIES.md)**.

## Legal / safety

For authorized security education, SAST evaluation, and CTF-style practice only.
Runs an unauthenticated remote-code-execution surface by design — keep it on
`localhost` / an isolated lab network. You are responsible for how you use it.
