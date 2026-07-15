# vulnerable-web-app

> ⚠️ **Intentionally vulnerable.** A runnable Java + JavaScript + SQL web app
> ("VulnShop") with **28 planted, exploitable vulnerabilities** (36 sink
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
| `VULNERABILITIES.md` | The list of all 28 planted vulns (CWE, location, entry point) |
| `docs/` | Architecture + copy-paste exploitation guide |
| `poc/` | `exploit_all.py` — automated end-to-end exploits (proves they fire) |
| `checker/` | `build_reference.py` (ground truth) + `sast_checker.py` (scorer) + `reference.sarif` |

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

```bash
pip install -r poc/requirements.txt
python3 poc/exploit_all.py                 # runs every exploit, prints PASS/FAIL
python3 poc/exploit_all.py --only sqli,xxe # subset
```

Expected: `RESULT: 14/14 exploits succeeded`. See `docs/exploitation-guide.md`
for the `curl` version of each.

## 3. Benchmark a SAST tool

The ground-truth SARIF is generated straight from `VULN:VULN-x:CWE-n` markers in
the source, so line numbers always match the code:

```bash
python3 checker/build_reference.py         # (re)build checker/reference.sarif — 36 findings
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

## Vulnerability classes (28)

SQLi (×2), reflected + stored + DOM XSS, OS command injection, path traversal,
unrestricted upload, insecure deserialization, XXE, SSRF, open redirect, unsafe
reflection, IDOR, sensitive-data exposure, missing authentication, verbose
errors, insecure/predictable session cookies, weak crypto (MD5, hard-coded AES
key, static IV), hard-coded secrets (server + JS), insecure SQL schema (unsalted
passwords, cleartext storage, excessive privileges), client-side `eval`.

Full table with CWE ids and locations: **[`VULNERABILITIES.md`](VULNERABILITIES.md)**.

## Legal / safety

For authorized security education, SAST evaluation, and CTF-style practice only.
Runs an unauthenticated remote-code-execution surface by design — keep it on
`localhost` / an isolated lab network. You are responsible for how you use it.
