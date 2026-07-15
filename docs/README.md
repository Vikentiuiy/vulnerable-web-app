# Docs

- [`../VULNERABILITIES.md`](../VULNERABILITIES.md) — the full list of planted
  vulnerabilities (28 items / 36 sink locations) with CWE, location and entry point.
- [`architecture.md`](architecture.md) — how the app is structured (tiers,
  controllers, data model, Docker layout).
- [`exploitation-guide.md`](exploitation-guide.md) — copy-paste `curl` exploits
  for every vulnerability.

## The SAST benchmark loop

```
                         checker/build_reference.py
 source markers  ───────────────────────────────────────►  checker/reference.sarif
 (VULN:VULN-x:CWE-n)                                              (ground truth)
                                                                       │
 your SAST tool  ─────────────►  tool_output.sarif                     │
                                        │                              │
                                        ▼                              ▼
                                 checker/sast_checker.py  ──►  recall / precision / F1
```

Run your SAST tool over the repo, export SARIF, then:

```bash
python3 checker/sast_checker.py -r checker/reference.sarif -a tool_output.sarif
```

See the top-level [`README.md`](../README.md) for matching-mode options.
