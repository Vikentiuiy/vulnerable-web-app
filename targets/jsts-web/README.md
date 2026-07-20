# jsts-web — Node / Express / TypeScript target

A vulnerable **Node.js + Express** app written in **TypeScript**, exploited over HTTP.
Includes a JS-specific **prototype pollution** sink. This target also demonstrates a
critical scan-config finding: **PT AI's JS engine analyses compiled `.js`, not `.ts`.**

## Technologies & libraries

| Piece | Choice |
|-------|--------|
| Language | **TypeScript 5** (compiled to CommonJS with `tsc`) |
| Framework | **Express 4** (one `Router` per vuln, imported in `app.ts`) |
| Database | **better-sqlite3** (native module, synchronous API) |
| HTTP client | **axios** (SSRF sink) |
| Base image | `node:20` (has the toolchain to build better-sqlite3) |

## Structure

```
src/app.ts             express app, static router imports, body parsers, harness detector
src/store.ts           better-sqlite3 in-memory DB + seed (unsalted MD5, cleartext secret)
src/vulns/vulnNN_*.ts  one Router = one endpoint = one sink (1:1)
src/harness/           catalog + tracker + response-capturing middleware  (excluded from the scan)
tsconfig.json          target ES2020, outDir dist/
Dockerfile             npm install → npx tsc → run dist/app.js
```

Routers are **statically imported** in `app.ts` (not dynamically `require`d) so a
SAST can see every Express entry point.

## Run it

```bash
docker compose up -d --build          # app on :8083
python3 exploits/exploit_all.py       # "RESULT: 25/25 exploits succeeded"
docker compose down
```

25 vulns including prototype pollution (`CWE-1321`) and `eval` code injection — see
[`VULNERABILITIES.md`](VULNERABILITIES.md).

## Benchmark note (important)

PT AI's taint engine returns **0 findings on the `.ts` source** but **42% on the
compiled `.js`** of the same code (PatternMatching still regex-scans `.ts`). So this
target must be scanned as its **build output** for a fair engine measurement:

```bash
./build-dist.sh          # compiles src/ -> dist/ (locally via tsc, or via Docker+docker cp),
                         # then scan dist/ as JavaScript (ProgrammingLanguages: ["JavaScript"],
                         # --excludes "**/harness/**"). Engine: 42% vs 0% on the .ts source.
```

Semgrep, by contrast, reads `.ts` directly (58%). See
[`../../benchmark/README.md`](../../benchmark/README.md).
