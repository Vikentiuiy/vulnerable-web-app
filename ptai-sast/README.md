# ptai-sast — PT AI CLI wrapper

Standalone folder to scan a code archive with **PT Application Inspector** and get a
**SARIF** report. Just the jar + a wrapper script.

```
ptai-sast/
├── ptai-cli-plugin.jar    the PT AI EE CLI (POSIdev-community/ptai-ee-tools)
├── script.sh              wrapper — scan / check / templates / report, with --help
└── config.example.json    a scan-settings template (customer b63d419a default)
```

## Requirements
- **Java 11+** (a local `java`) — or Docker with the `ptai-cli:local` image. The script
  auto-detects; force one with `-runner java|docker`.
- `unzip` (only if you pass a `.zip` archive).
- Network access to the PT AI server + an **API token**.

## Quick start
```bash
chmod +x script.sh
export PTAI_TOKEN=<your-api-token>            # or pass -token
export PTAI_URL=https://ptaiserver.ptai.local # optional (this is the default)

# scan a zipped codebase with a config -> result SARIF ('scan' is the default command)
./script.sh -archive code_archive.zip -config config.example.json

# or a source folder directly, with a custom output + excludes
./script.sh scan -archive ./src -config config.example.json -out result.sarif -excludes '**/test/**'
```

## Commands
| Command | Does |
|---------|------|
| `scan` (default) | scan `-archive` (zip or folder) with `-config` JSON → SARIF |
| `check` | verify server connection + license |
| `templates` | list report templates on the server |
| `report` | generate an HTML/PDF report for a scanned `-project` |
| `help` | full usage |

`./script.sh help` lists every option. Token/URL can come from `-token`/`-url` or the
`PTAI_TOKEN`/`PTAI_URL` environment variables.

## The config (`-config`)
A PT AI `.aiproj` JSON (scan settings). `config.example.json` is the customer default
(`StaticCodeAnalysis` engine, all languages, `UsePublicAnalysisMethod: true`). Edit
`ProgrammingLanguages` / `ScanModules` to taste. Key fields:
- `ScanModules`: `StaticCodeAnalysis` (taint engine) `+ PatternMatching + Configuration
  + Components + SoftwareCompositionAnalysis`.
- `ProgrammingLanguages`: list what to analyse (unused languages can be removed).

## Notes
- TLS to the lab cert is trusted by default (`-k`); pass `-no-insecure` to verify.
- The harmless `WARNING: sun.reflect...` line (newer JDKs) is filtered out.
- SARIF can be scored against a ground-truth reference with the benchmark's
  `checker/sast_checker.py`.
