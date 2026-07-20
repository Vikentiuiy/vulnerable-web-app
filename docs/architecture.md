# Architecture

A **monorepo of independent, per-language targets** for benchmarking SAST tools.
Each target is a self-contained, Dockerised, exploitable application (or native
binary set) that plants a known set of vulnerabilities; shared tooling scans and
scores every target the same way.

```
vuln-sast-benchmark/
├── targets/<lang>/        one self-contained target per language (see contract below)
├── checker/               shared, tool-agnostic SARIF scoring
│   ├── build_reference.py     ground-truth SARIF from source markers
│   ├── sast_checker.py        score a tool's SARIF (per detection-class recall / precision)
│   └── verify_contract.py     marker ⟷ catalog ⟷ exploit ⟷ reference sync gate
├── ptai/                  PT AI automation + reporting
│   ├── scan.sh, run_ablation.sh, summary.sh, compare_tools.sh
│   ├── compare_profiles.py, gen_report.py, pack.sh
└── docs/                  methodology, this file, the visual report
```

## The target contract

Every `targets/<lang>/` exposes the same artifacts, so one set of tools drives all:

| Artifact | Purpose |
|----------|---------|
| `src/…` (or `Sources/`, `db/`) with `VULN:VULN-xx:CWE-nnn:class` markers | the vulnerable code — **only this is scanned** |
| `harness/` | live-exploit instrumentation (tracker, catalog, detection filter) — **excluded from the scan** |
| `Dockerfile` + `docker-compose.yml` | build & run gate |
| `scope.txt` | Ant-glob excludes so the scanner sees only vulnerable code |
| `reference.sarif` | ground truth, generated from this target's markers |
| `exploits/exploit_all.py` | runtime PoC that proves every planted vuln fires |
| `profiles/*.aiproj` | PT AI scan profiles (`default`=engine, `pm`, `config`, `max`, `refconfig`) |

### Two design rules that keep the statistics honest

1. **1:1 — one file = one primary sink.** Each vulnerability lives in its own real,
   wired endpoint/binary. This removes marker-clustering ambiguity and makes false-
   positive attribution exact.
2. **Instrumentation lives outside the scanned code.** The live dashboard is driven
   by an external filter/hook in `harness/` (excluded via `scope.txt`), so the sink
   files the SAST sees contain only the vulnerability — no detector noise.

A vulnerability only counts once it (1) builds, (2) runs, (3) is exploited by a
passing PoC, and (4) is in sync across marker ⟷ catalog ⟷ exploit ⟷ reference.

## Targets

| Target | Stack | Exploitation model | Port |
|--------|-------|--------------------|------|
| `java-web` | Spring Boot (Java + SQL + browser JS) | HTTP | 8080 |
| `kotlin-web` | Kotlin + Spring Boot + H2 | HTTP | 8081 |
| `python-web` | Python + Flask + SQLite | HTTP | 8082 |
| `jsts-web` | Node/Express + TypeScript | HTTP | 8083 |
| `swift` | Swift + Vapor | HTTP | 8084 |
| `sql-app` | Flask + MySQL (SQL taint via HTTP) | HTTP + DB | 8085 |
| `sql` | MySQL schema + stored procedures | DB | 3307 |
| `cpp` | native C, built with & without ASAN | crafted input → ASAN crash | — |

## Detection classes

Every planted vuln is tagged with the analysis class needed to detect it, and
scoring is done **per class** — never blended:

- `taint` — real source→sink dataflow (the **engine**; headline metric)
- `pattern` — local signature / bad-API usage (PatternMatching)
- `config` — insecure schema / settings / headers (Configuration)
- `sca` — vulnerable dependency (Components / SCA)
- `logic` — business-logic / access-control (usually expected static FN)

See [`benchmark-methodology.md`](benchmark-methodology.md) for the full scoring model.
