# Scan profiles — what each config means

Each target has several PT AI scan profiles under `targets/<t>/profiles/*.aiproj`.
They differ **only** in which scan modules and settings are enabled, so a comparison
between them isolates the contribution of each module. All figures in the benchmark
name the exact profile they came from.

## The profiles

| Profile | `ScanModules` | `ApplyAllPMRules` | `DownloadDependencies` | Languages | Measures |
|---------|---------------|:--:|:--:|-----------|----------|
| **`default`** | `StaticCodeAnalysis` | false | false | the target's own (e.g. `Java, JavaScript, Sql`) | **the pure taint engine** — the headline number |
| **`refconfig`** | `StaticCodeAnalysis` | false | false | **all 13** (your `b63d419a` default) | the **customer default config**, untrimmed |
| **`pm`** | `+ PatternMatching` | **true** | false | target's own | engine **+ signature rules** |
| **`config`** | `+ Configuration` | false | false | target's own | engine **+ configuration analysis** |
| **`max`** | `+ PatternMatching + Configuration + Components + SoftwareCompositionAnalysis` | **true** | **true** | target's own | **everything**, including dependency (SCA) findings |

Every profile also sets `UsePublicAnalysisMethod: true` (see below), and the web
targets keep `UseTaintAnalysis: true` + `UseJsaAnalysis: true` for JavaScript.

## `default` vs `refconfig` — the important one

Both are **the same thing**: the `StaticCodeAnalysis` module alone (the taint /
dataflow engine), with `UsePublicAnalysisMethod: true`. They differ in exactly one
field:

- **`refconfig`** is the customer's `b63d419a` settings **verbatim** — it lists **all
  13 `ProgrammingLanguages`**. This is "the default config you gave me".
- **`default`** is the same config with the **language list trimmed** to the ones the
  target actually contains (which the customer settings explicitly allow — *"you can
  only disable languages that aren't used"*).

Trimming languages that have no files changes nothing, and the benchmark proves it:
`refconfig` produced the **identical taint-recall as `default` on all 8 targets**.
So wherever you read "the engine" or "`default`", it is exactly your customer
default config, just without the unused-language noise. `default` is used as the
headline label because it is per-target and reproducible.

## What each module is

| Module | Role |
|--------|------|
| **`StaticCodeAnalysis`** | the core **taint / dataflow engine** — traces user input from a source to a dangerous sink. This is what "engine recall" measures. |
| **`PatternMatching`** | signature rules that flag risky API usage locally (e.g. `MD5`, `strcpy`, insecure cookie flags), no dataflow required. `ApplyAllPMRules: true` turns on the full rule set. |
| **`Configuration`** | analysis of configuration / manifest files (headers, framework settings). |
| **`Components` / `SoftwareCompositionAnalysis`** | **SCA** — known-vulnerable dependencies. `DownloadDependencies: true` lets it resolve the dependency tree. These findings are a **separate axis** and are excluded from code-recall figures. |

## Why `UsePublicAnalysisMethod: true` matters

It tells the engine to treat every **public method as an entry point** for taint. With
it `false`, the engine only analyses code reachable from entry points it recognises,
and (measured on this stand) it then **misses XXE and deserialization** that it
otherwise catches. All profiles here set it `true`, matching your customer default,
so the engine is never handicapped.

## How to reproduce

```bash
ptai/scan.sh targets/<t> default   results/<t>-default.sarif    # pure engine
ptai/scan.sh targets/<t> refconfig results/<t>-refconfig.sarif  # your b63d419a default
ptai/run_ablation.sh targets/<t>                                # default→pm→config→max
```

The `.aiproj` files in `targets/<t>/profiles/` are the literal, editable settings sent
to PT AI. See [`benchmark-methodology.md`](benchmark-methodology.md) for the scoring
model and [`../benchmark/`](../benchmark) for the committed results.
