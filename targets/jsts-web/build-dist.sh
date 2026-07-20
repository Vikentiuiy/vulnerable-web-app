#!/usr/bin/env bash
# Produce the compiled JavaScript (dist/) that PT AI's engine can actually analyse.
# PT AI models JavaScript, not TypeScript — it finds ~0 on .ts but ~42% on the .js
# that `tsc` emits (types erased, modules/enums/decorators lowered to plain ES).
#
#   targets/jsts-web/build-dist.sh          # -> targets/jsts-web/dist/*.js
#
# Then scan dist/ as JavaScript (see the README) or:
#   ptai/scan.sh already scans src/ — point a scan at this dist/ instead for the
#   fair engine measurement.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

if command -v npx >/dev/null 2>&1 && [ -d node_modules ]; then
  echo ">> compiling locally with tsc"
  npx tsc
else
  echo ">> compiling inside Docker (no local Node needed)"
  docker compose up -d --build >/dev/null
  rm -rf dist
  docker cp vuln-jsts-web:/app/dist ./dist
  docker compose down >/dev/null            # tear down — don't hold RAM
fi

echo ">> compiled JS ready in $HERE/dist ($(find dist -name '*.js' | wc -l) files)"
echo "   scan it as JavaScript with harness excluded (see README §Benchmark note)."
