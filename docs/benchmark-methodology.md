# SAST benchmark methodology — measuring the engine, honestly

This document is the source of truth for **how we measure PT AI (and any SAST)**
against the vulnerable fixtures, and for the design rules that keep the FP/FN
statistics *relevant*. It is the result of empirical work against the live PT AI
6.1.1 stand (see the ablation results below).

## 0. The one goal

Measure **how good the SAST engine itself is** — its ability to trace tainted
data from source to sink and reason about code — separated from add-on modules
(pattern matching, configuration analysis, SCA/dependencies) and separated from
artifacts introduced by our own fixtures or scoring.

Everything below serves that goal.

## 1. Detection-class taxonomy (per planted vulnerability)

Every planted vulnerability is tagged with the **class of analysis required to
detect it**. Scoring is done *per class*, never as one blended number.

| Class | Meaning | Example planted vulns | Which PT AI module |
|-------|---------|----------------------|--------------------|
| `taint` | Real source→sink dataflow the **engine** must trace | SQLi, OS command, path traversal, SSRF, XXE, deserialization, XPath, unsafe reflection, open redirect, SpEL, reflected/stored/DOM XSS, log injection | StaticCodeAnalysis (the engine) |
| `pattern` | Local signature / bad API usage, no dataflow needed | weak hash (MD5), hardcoded key, static IV, insecure cookie flags, `eval` presence | PatternMatching |
| `config` | Insecure configuration / manifest / properties | clickjacking headers, cookie http-only, verbose errors | Configuration |
| `sca` | Known-vulnerable dependency | vulnerable `commons-collections4`, etc. | Components / SoftwareCompositionAnalysis |
| `logic` | Business-logic / access-control / semantic — generally **not** statically detectable | IDOR, missing auth, mass assignment, no rate limiting, integer overflow, predictable token | (usually none — expected FN) |

**Headline metric = engine recall** = detected / (vulns tagged `taint`).
`pattern`, `config`, `sca` are reported as separate deltas. `logic` vulns are
tracked but excluded from the engine score (they are expected static FN and are
there for realism / exploitation, not to penalise the engine).

## 2. Scan profiles (ablation protocol)

Profiles are built from the customer "reference" default (aiproj 1.9,
`UsePublicAnalysisMethod: true` everywhere). We vary **one module at a time** to
attribute each module's contribution.

| Profile | ScanModules | Purpose |
|---------|-------------|---------|
| `default` | `StaticCodeAnalysis` | **the pure engine** — headline |
| `pm` | `+ PatternMatching` (`ApplyAllPMRules`) | delta of signature rules |
| `config` | `+ Configuration` | delta of config analysis |
| `max` | `+ Components + SoftwareCompositionAnalysis` (`DownloadDependencies`) | full, incl. dependency axis |

> `BlackBox` (DAST) is out of scope for a static benchmark.
> `UsePublicAnalysisMethod: true` is mandatory — with it `false`, the engine
> misses XXE/deserialization purely due to entry-point resolution (measured).

### First ablation result (against the *pre-redesign* fixture — provisional)

| Profile | raw findings | Δ vs default | notes |
|---------|--------------|--------------|-------|
| default (engine) | 21 | — | pure taint sinks, precision 100% on located findings |
| + PatternMatching | 39 | **+18** | +2 real (weak MD5, insecure cookie), +16 hygiene/noise (mostly `dashboard.js`) |
| + Configuration | 21 | **+0** | our config vulns not detected by this module |
| max (+SCA) | 132 | +93 SCA | dependency findings — a *different axis*, excluded from code scoring |

**Engine gaps observed (genuine, all profiles):** all XSS (reflected/stored/DOM),
open redirect, SpEL, client-side `eval` — real taint paths the engine did not
raise. This is the valuable benchmark signal.

> ⚠️ These numbers are **provisional**. They must be recomputed on the final 1:1
> fixture and re-verified repeatedly before being treated as conclusions.

## 3. Fixture design rules (keep the statistics relevant)

1. **One file = one primary sink** per vulnerability. Each file is a real, wired,
   exploitable `@RestController`/endpoint — not a dead snippet. Eliminates
   marker-clustering cross-class steals and makes FP attribution exact.
   - Exceptions: chained/multi-location vulns keep one *primary* sink file plus
     shared infra (schema, crypto util); config/schema vulns live in their
     natural files.
2. **Instrumentation lives outside the scanned code.** The live-exploit tracker
   is an external servlet filter in a `harness` package, excluded via `scope`.
   No detector regexes / `tracker.mark(...)` inside sink files.
3. **Scan scope excludes the harness** (dashboard, tracker, catalog, stray test
   files). Enforced with the CLI `--excludes` (Ant globs) derived from `scope`.
4. **Reference = one primary sink line per vuln**, tagged with CWE **and**
   detection-class. Generated from `VULN:VULN-xx:CWE-nnn:class` markers.
5. **Exploit gate:** every planted vuln has a runtime PoC that fires; a vuln
   without a passing exploit does not count. Contract check keeps
   marker ⟷ exploit ⟷ catalog in sync.

## 4. Known scoring-corruption sources and status

| # | Corruption | Effect on stats | Fix | Status |
|---|-----------|-----------------|-----|--------|
| 1 | Instrumentation woven into sinks (detector regexes, `tracker.mark`) | spurious FP near sinks | external filter + scope | pending (fixture rebuild) |
| 2 | Harness files in scan scope (`dashboard.js` ×11, `ReTest.java`) | ~35% of findings are noise | `scope` excludes | pending (fixture rebuild) |
| 3 | Marker clustering within ±tolerance of a different-CWE marker | cross-class steal inflates recall | 1:1 file-per-vuln | pending (fixture rebuild) |
| 4 | Reference twins (template/multi-line mirrors) inflate denominator | recall understated | one primary sink per vuln | pending (fixture rebuild) |
| 5 | `in_source` only counted `.java` under `/vulnapp/` | FP in `.js/.sql/.html` silently dropped → precision overstated | broaden to all source exts | **fixed** (checker) |
| 6 | Line-less (SCA) findings match planted sinks by filename | fake recall (73% observed) | require a line for location match; SCA → dependency bucket | **fixed** (checker, `--allow-fileonly-match` restores old) |
| 7 | Denominator mixes taint/pattern/config/logic vs the engine | engine recall understated | per-detection-class scoring | pending (checker + reference) |
| 8 | `UsePublicAnalysisMethod: false` in ad-hoc scans | engine misses XXE/deser | mandate `true` in all profiles | **fixed** (profiles) |

## 4a. Cross-language engine results (measured, provisional — re-verify)

Engine = `StaticCodeAnalysis` profile, `publicMethod=true`, taint-class recall:

| target | engine taint-recall | precision | notes |
|--------|--------------------:|----------:|-------|
| java-web   | 11/18 = **61.1%** | 94% | strongest; misses XSS/open-redirect/SpEL |
| python-web |  7/16 = **43.8%** | 100% | engine misses sqlite3 SQLi (only PM catches it) |
| jsts-web   |  5/12 = **41.7%** | — | **compiled JS only** (see caveat); catches XSS(9)+open-redirect, misses better-sqlite3 SQLi |
| kotlin-web |  5/15 = **33.3%** | 100% | misses path/SSRF/deser/XXE/log that Java catches |
| cpp        |  1/11 = **9.1%**  | 33% | ⚠ engine barely detects memory-safety — finds only double-free, misses stack/heap overflow, UAF, OOB, format string, int-overflow |
| sql        |  0/3  = **0.0%**  | — | ⚠ standalone SQL (schema + stored procs) yields **0 findings** across all profiles — files are uploaded but the engine flags nothing; PT AI detects SQLi via application-language taint, not by analysing pure `.sql` |
| sql-app    |  2/8  = **25%**   | 100% | ⚠ Flask+MySQL adds a live HTTP taint source; PT AI flags the **cmd-injection positive controls** but misses **every SQL injection** (5 variants: concat, f-string, .format, login, proc-mediated). Combo file `vuln89_combo.py`: same param → cmd sink (line 18, FLAGGED) + SQL sink (line 21, MISSED). Ironclad **Python SQL-injection blind spot** |
| swift      |  0/7  = **0.0%**  | — | ⚠ Vapor Swift app — 0 findings across all profiles though files uploaded (11 KB); PT AI has essentially **no working Swift analysis** here |

**Ironclad blind-spot proofs** (positive control in the same code eliminates
pipeline/entry-point/reachability as explanations):
- **Python SQLi:** `sql-app/vulns/vuln89_combo.py` — same `term` → cmd (line 18 flagged) + SQL (line 21 missed).
- **XSS:** `python-web/vulns/vuln91_xss_combo.py` — same `q` → cmd (line 16 flagged) + reflected HTML (line 18 missed); 5 XSS contexts, 0 XSS found anywhere.
- **C memory-safety:** cpp has 20 canonical sinks from argv/stdin/env/file → engine 1/19 (5.3%); only pattern bugs (double-free, format-string, leak) caught.

Module deltas are consistent across languages: `PatternMatching` adds a few real
signatures (weak MD5, cookie flags) plus code-quality noise; `Configuration` adds
~nothing on these fixtures; `Components/SCA` is a separate dependency axis
(line-less findings, excluded from code recall).

**⚠️ TypeScript caveat (critical):** PT AI's JS taint engine returns **0 findings
on `.ts` source** but **19 on the compiled `.js`** of the identical code
(`PatternMatching` still regex-scans `.ts`). jsts-web must therefore be scanned as
its **compiled `dist/*.js`** (e.g. `docker cp <container>:/app/dist`), not the TS
source, or the engine measurement is a false zero. XSS is otherwise a universal
engine gap (missed on Java/Kotlin/Python; found only on JS).

## 5. Running a scan (validated recipe, PT AI 6.1.1)

Auth: `GET /api/auth/signin` with header `Access-Token: <API_TOKEN>` → JWT;
thereafter `Authorization: Bearer <JWT>`. SARIF is generated client-side, so we
drive scans through the official CLI (built from `POSIdev-community/ptai-ee-tools`,
image `ptai-cli:local`):

```bash
docker run --rm --add-host ptaiserver.ptai.local:192.168.1.105 \
  -v <target/src>:/work/src:ro -v <profile.aiproj>:/work/s.aiproj:ro -v <out>:/work/out \
  ptai-cli:local ptai-cli-plugin json-ast \
    --url https://ptaiserver.ptai.local --token <API_TOKEN> \
    --settings-json /work/s.aiproj --input /work/src \
    --sarif-report-file /work/out/result.sarif \
    --excludes "<harness globs>" --insecure
```

Score: `python3 checker/sast_checker.py -r <target>/reference.sarif -a result.sarif`.
