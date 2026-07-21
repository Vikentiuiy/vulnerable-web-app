# vuln-sast-benchmark

> ⚠️ **Intentionally vulnerable.** A multi-language benchmark for evaluating SAST
> tools (built for **PT Application Inspector**, works with any SARIF-emitting
> tool). Every planted vulnerability is **real and exploitable end-to-end in
> Docker** — not a static snippet. **DO NOT DEPLOY** on any reachable network.

The goal is an **honest, per-language, per-detection-class** measurement of how
well a SAST tool — and especially its **core engine** — finds real vulnerabilities,
with FP/FN statistics that are not corrupted by fixture or scoring artifacts.
See **[`docs/benchmark-methodology.md`](docs/benchmark-methodology.md)**.

## Layout

```
targets/            one self-contained, independently-scannable target per language
  java-web/         Java + SQL + browser-JS (Spring Boot)   [reference target]
  kotlin-web/       Kotlin (Spring Boot + H2)               [done: 31 vulns]
  python-web/       Python (Flask + SQLite)                 [done: 33 vulns]
  jsts-web/         Node/Express + TypeScript               [done: 25 vulns]
  sql/              MySQL schema + stored-proc weaknesses   [done: 7 vulns]
  sql-app/          Flask + MySQL (SQL taint via HTTP)       [done: 16 vulns]
  cpp/              native ASAN-verified memory-safety bugs [done: 20 vulns]
  swift/            Swift (Vapor)                           [done: 20 vulns]
checker/            shared, tool-agnostic: build_reference.py + sast_checker.py
ptai/               shared PT AI automation: scan.sh, run_ablation.sh, compare_profiles.py
docs/               methodology + guides
benchmark/          COMMITTED pre-computed results (CSV, SARIFs, report, conclusions)
ptai-sast/          standalone PT AI CLI wrapper (jar + script.sh) — scan an archive anywhere
```

## The target contract

Every `targets/<lang>/` provides the same artifacts, so tooling is shared:

| Artifact | Purpose |
|----------|---------|
| `src/…` with `VULN:VULN-xx:CWE-nnn:class` markers | the vulnerable code — **only this is scanned** |
| `Dockerfile` (+ `docker-compose.yml`) | build & run gate |
| `scope.txt` | Ant-glob excludes so the scanner sees only vulnerable code (harness excluded) |
| `reference.sarif` | ground truth, generated from this target's markers |
| `exploits/` | runtime PoC that proves every planted vuln fires |
| `profiles/*.aiproj` | scan profiles (`default`=engine, `pm`, `config`, `max`) |

A vulnerability only counts once it (1) builds, (2) runs, (3) is exploited by a
passing PoC, and (4) is in sync across marker ⟷ exploit ⟷ catalog.

## Requirements

- **Docker** + Docker Compose (every target builds & runs in Docker).
- **Python 3** with `requests` for the exploit suites: `pip install requests`.
- For SAST scanning: a reachable **PT AI** server + API token, and the CLI image
  (built once, below). OSS comparison additionally pulls the `semgrep/semgrep` image.

## Targets & ports

| Target | Stack | Port | Exploit gate |
|--------|-------|------|--------------|
| `java-web`   | Spring Boot (Java+SQL+JS) | 8080 | `40/40` HTTP |
| `kotlin-web` | Spring Boot + H2          | 8081 | `31/31` HTTP |
| `python-web` | Flask + SQLite            | 8082 | `33/33` HTTP |
| `jsts-web`   | Node/Express + TypeScript | 8083 | `25/25` HTTP |
| `swift`      | Vapor                     | 8084 | `20/20` HTTP |
| `sql-app`    | Flask + MySQL             | 8085 | `16/16` HTTP + DB |
| `sql`        | MySQL schema + procs      | 3307 | `7/7` DB |
| `cpp`        | native C + ASAN           | —    | `20/20` ASAN |

## 1. Build, run & prove exploitability (any target)

```bash
cd targets/<target>
docker compose up -d --build          # build + start the vulnerable app
python3 exploits/exploit_all.py       # fires every exploit, prints N/N succeeded
docker compose down -v                # tear down
```

Or from the repo root via the Makefile: `make test TARGET=<target>`
(goals: `build up down exploit reference scan ablation`; `make list` shows targets).
`cpp` and `sql` have no web port — their exploit gate runs against the container
(ASAN crashes / DB), so bring the container up first, then run the suite.

## 2. Ground truth

```bash
python3 checker/build_reference.py --root targets/<target> -o targets/<target>/reference.sarif
python3 checker/verify_contract.py targets/<target>   # marker⟷catalog⟷exploit⟷reference in sync
```

## 3. Scan with PT AI & score

```bash
# one-time: build the PT AI CLI image from POSIdev-community/ptai-ee-tools
git clone --depth 1 https://github.com/POSIdev-community/ptai-ee-tools /tmp/ptai-ee-tools
docker build -t ptai-cli:local /tmp/ptai-ee-tools

export PTAI_TOKEN=<your-api-token>     # PTAI_URL / PTAI_HOST_IP override the defaults
ptai/scan.sh targets/<target> default results/<target>-default.sarif   # engine profile
python3 checker/sast_checker.py -r targets/<target>/reference.sarif -a results/<target>-default.sarif

ptai/run_ablation.sh targets/<target>  # default→+PM→+Config→+max, per-module deltas
ptai/summary.sh                        # aggregate engine recall across all scanned targets
```

## 4. Compare against open-source SAST (Semgrep)

```bash
docker run --rm -v "$PWD":/repo -w /repo semgrep/semgrep \
  semgrep scan --config auto --sarif -o results/semgrep-<target>.sarif \
  --exclude harness --exclude exploits targets/<target>/src
ptai/compare_tools.sh <target> results/<target>-default.sarif results/semgrep-<target>.sarif Semgrep
```

## 5. Visual report

```bash
python3 ptai/gen_report.py             # writes docs/report.html from results/report_data.json
```

## 6. Pack a clean archive for any SAST UI

```bash
ptai/pack.sh targets/<target>          # dist/<target>-scan.zip — vulnerable code ONLY
```
Strips the harness, exploits, build output and deps per `scope.txt`, so an unfamiliar
user can't accidentally upload the whole repo.

## Legal / safety

For authorized security education and SAST evaluation only. Runs unauthenticated
RCE surfaces by design — keep on `localhost` / an isolated lab network.
