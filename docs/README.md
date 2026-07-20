# Docs

- [`benchmark-methodology.md`](benchmark-methodology.md) — **how we measure**:
  detection-class taxonomy, engine-first scoring, scan profiles, the scoring-
  corruption fixes, and the cross-language results.
- [`architecture.md`](architecture.md) — monorepo layout, the target contract, the
  1:1 design rules, and the target/port map.
- [`exploitation-guide.md`](exploitation-guide.md) — how each target is exploited
  (automated suite + representative `curl`s on the 1:1 endpoints).
- [`report.html`](report.html) — the visual benchmark report (also published as an
  artifact). Regenerate with `python3 ptai/gen_report.py`.
- **Per target**: `targets/<lang>/VULNERABILITIES.md` — the full planted-vuln table
  (id · CWE · detection class · endpoint · sink location).
- **Committed results**: [`../benchmark/`](../benchmark/) — pre-computed scan
  SARIFs, CSV, and the analysis writeup, so you can read the numbers without running
  a scan.

## The SAST benchmark loop

```
                        checker/build_reference.py
 source markers  ──────────────────────────────────────►  targets/<t>/reference.sarif
 (VULN:VULN-x:CWE-n:class)                                       (ground truth)
                                                                       │
 SAST tool (PT AI / Semgrep / …)  ──►  results/<t>-<profile>.sarif     │
                                              │                        │
                                              ▼                        ▼
                                    checker/sast_checker.py  ──►  per-class recall /
                                                                  precision (engine=taint)
```

```bash
# ground truth for a target
python3 checker/build_reference.py --root targets/<t> -o targets/<t>/reference.sarif
# score any tool's SARIF against it
python3 checker/sast_checker.py -r targets/<t>/reference.sarif -a results/<t>-default.sarif
```

See the top-level [`README.md`](../README.md) for the full run guide (build,
exploit, scan, compare, report, pack).
