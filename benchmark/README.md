# Benchmark results — PT Application Inspector taint-engine capabilities

Pre-computed, committed results so you can read the numbers without running a scan.
Every figure here is reproducible with `ptai/run_ablation.sh` + `checker/sast_checker.py`. Profiles are documented in [`../docs/scan-profiles.md`](../docs/scan-profiles.md)
against the exploit-verified fixtures in `targets/`.

| File | What |
|------|------|
| [`engine-recall.csv`](engine-recall.csv) | long-format table: target × tool × profile → taint-recall / precision / findings |
| [`report.html`](report.html) | the visual dashboard (open in a browser) |
| [`report_data.json`](report_data.json) | machine-readable, per-class scores |
| [`sarif/`](sarif) | the raw scan SARIFs (PT AI `default/pm/config/max/refconfig`, Semgrep, jsts compiled-JS) |

**Metric.** *Taint-class recall* = fraction of the planted **dataflow (source→sink)**
vulnerabilities the tool's core engine detects. This isolates the engine from the
pattern-matching / configuration / dependency modules. All ground truth is
marker-generated and every finding is independently **exploit-verified** (HTTP PoC
or ASAN crash).

---

## 1. Pure taint engine — the headline

`default` is PT AI's `StaticCodeAnalysis` module alone (the taint engine). The
customer's own default config (`refconfig`, the `b63d419a` settings you provided —
`StaticCodeAnalysis`, all languages, `UsePublicAnalysisMethod=true`) produces the
**identical** result on every target, so this is a definitive measure of the engine:

| Language | PT AI engine (`default` = `refconfig`) | Semgrep |
|----------|:--:|:--:|
| Java     | **61%** (11/18) | 56% |
| Python   | **40%** (8/20)  | 85% |
| Kotlin   | **33%** (5/15)  | 0%  |
| JS/TS    | **0%** on `.ts` · **42%** on compiled JS | 58% (`.ts`) |
| SQL-app  | **15%** (2/13)  | 88% |
| C/C++    | **5%** (1/19)   | 5%  |
| SQL (standalone) | **0%** | — |
| Swift    | **0%** (0/9)    | — |

> **`refconfig` ≡ `default` on all 8 targets.** Your customer config and the pure
> taint engine are the same measurement — trimming unused languages changes nothing.

## 2. What each scan module adds (ablation)

Taint-recall as modules are switched on one at a time
(`default → +PatternMatching → +Configuration → +Components/SCA = max`):

| Language | default | +PatternMatching | +Configuration | max |
|----------|:--:|:--:|:--:|:--:|
| Java     | 61% | 61% | 61% | 61% |
| Python   | 40% | 50% | 40% | 50% |
| Kotlin   | 33% | 33% | 33% | 33% |
| JS/TS (`.ts` source) | 0% | 8% | 0% | 8% |
| JS/TS (**compiled `.js`**) | **42%** | **50%** | 42% | 50% |
| **C/C++** | **5%** | **84%** | 5% | **84%** |
| SQL-app  | 15% | 15% | 15% | 15% |
| SQL (standalone) | 0% | 0% | 0% | 0% |
| Swift    | 0% | 0% | 0% | 0% |

> `sql` and `swift` are **0 across every module** — the files upload but the engine
> flags nothing (no recognised taint source in pure `.sql`; no working Swift analysis
> on this stand).

- **PatternMatching is what rescues C/C++** (5% → 84%): the taint engine barely
  reasons about memory, but the signature rules catch the dangerous-function usage
  (`strcpy`/`sprintf`/`memcpy`/…). *PT AI does find C bugs — via PM, not dataflow.*
- **Configuration adds nothing** on these fixtures.
- **PatternMatching does NOT rescue Python SQLi/XSS** (SQL-app stays 15%): those
  are engine blind spots that no module covers.
- `max` also adds `Components/SCA` dependency findings — a separate axis, excluded
  from the code-recall figures above.

### `.ts` source vs compiled `.js` — why it matters for a SAST

The same code scores **0% on `.ts`** but **42% on the `.js`** `tsc` emits. In short:

- **TypeScript is a superset of JS** — type annotations, `import`/`export`, enums,
  decorators. PT AI's engine models **JavaScript** (the runtime language); without a
  full TS front-end it doesn't run *dataflow* on `.ts` (only pattern rules apply), so
  taint tracking effectively doesn't happen → ~0.
- **`tsc` erases the types** and lowers modules/enums/decorators to plain ES `.js` the
  engine fully understands — the *same logic* becomes analysable, so the sinks light up.
- **Takeaway:** scan the **build output** (`dist/`) of a TS project with PT AI, not the
  `.ts` source. (Semgrep has a native TS parser and reads `.ts` directly — 58%.)

## 3. PT AI engine vs Semgrep — complementary

The two engines cover **different** ground:

- **PT AI leads** on JVM injection: Java (61 vs 56) and Kotlin (33 vs **0** — Semgrep
  has essentially no Kotlin taint analysis).
- **Semgrep leads** exactly where PT AI is blind: Python SQLi/XSS (85 vs 40), the
  SQL-app SQLi (88 vs 15), and TypeScript read directly (58 vs 0 on `.ts`).
- **Both weak** on C memory-safety at the engine level (~5%).

## 4. Engine blind spots — ironclad proofs

Each proof puts a sink PT AI **does** flag next to one it **misses**, on the same
tainted variable, so the miss can't be a pipeline / entry-point / reachability
artifact (see `sarif/` and the `*_combo` files under `targets/`):

- **Python SQL injection** — `sql-app/vulns/vuln89_combo.py`: `subprocess.getoutput`
  (line 18) is flagged; `cursor.execute` (line 21) on the same `term` is missed.
  10 SQLi variants (concat, login, stored-proc, f-string, `.format`, ORDER BY, numeric, LIKE, UPDATE, IN) all missed.
- **Cross-Site Scripting** — `python-web/vulns/vuln91_xss_combo.py`: command
  injection (line 16) flagged; reflected HTML (line 18) on the same `q` missed. XSS
  is missed in every form on Java/Kotlin/Python (0 findings); caught only on JS.
- **C/C++ memory-safety** — 20 canonical bugs from every standard source
  (argv/stdin/env/file); the engine finds 3, all local patterns (double-free,
  format-string, leak). Every overflow / UAF / OOB / cmd / SQLi in C is missed by
  the engine (though PatternMatching catches 16/19 — see §2).

## 5. Conclusions on the taint engine

1. **Strong**: injection dataflow on the JVM (Java best of all tools measured).
2. **Reproducible blind spots**: Python SQL injection, XSS (Java/Kotlin/Python), and
   native C memory-safety as *dataflow* — each demonstrated with a working positive
   control beside it.
3. **Config that matters**: TypeScript must be scanned as its **compiled JS**
   (0% on `.ts`, 42% on `.js`); the customer default already has the right engine
   settings (`refconfig ≡ default`).
4. **Not the engine's model**: standalone SQL and Swift yield 0 — and adding an app
   taint source (`sql-app`) does not rescue Python SQLi.
5. **Modules are separate axes**: PatternMatching is essential for C; neither PM,
   Config nor SCA closes the Python-SQLi / XSS engine gaps.

## Reproduce

```bash
export PTAI_TOKEN=<token>
ptai/run_ablation.sh targets/<t>                 # default→pm→config→max
ptai/scan.sh targets/<t> refconfig results/<t>-refconfig.sarif
python3 ptai/build_data.py                        # → this CSV + report_data.json
python3 ptai/gen_report.py                        # → report.html
```
