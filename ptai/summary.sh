#!/usr/bin/env bash
# Aggregate the engine (taint-class) recall + precision across every target that
# has a default-profile scan in results/. Run after ptai/run_ablation.sh per target.
#   ptai/summary.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"

printf "%-12s %-8s %-10s %-11s %s\n" "TARGET" "VULNS" "ENGINE" "PRECISION" "SCAN"
printf -- "---------------------------------------------------------------\n"
for d in targets/*/; do
  t="$(basename "$d")"
  ref="$d/reference.sarif"
  sarif="results/$t-default.sarif"
  [ -f "$ref" ] || continue
  vulns="$(python3 -c "import json;print(sum(len(r['results']) for r in json.load(open('$ref'))['runs']))" 2>/dev/null || echo '?')"
  if [ -f "$sarif" ]; then
    rep="$(python3 checker/sast_checker.py -r "$ref" -a "$sarif" 2>/dev/null || true)"
    engine="$(echo "$rep" | grep 'taint' | head -1 | grep -oE '[0-9]+/[0-9]+ *= *[0-9.]+%' | tr -s ' ')"
    prec="$(echo "$rep" | grep -E '^ Precision ' | head -1 | grep -oE '[0-9.]+%' | head -1)"
    printf "%-12s %-8s %-10s %-11s %s\n" "$t" "$vulns" "${engine:-n/a}" "${prec:-n/a}" "default"
  else
    printf "%-12s %-8s %-10s %-11s %s\n" "$t" "$vulns" "-" "-" "(not scanned)"
  fi
done
printf -- "---------------------------------------------------------------\n"
echo "ENGINE = StaticCodeAnalysis taint-class recall (headline). See docs/benchmark-methodology.md."
echo "NOTE: jsts-web must be scanned as compiled JS (not .ts); see methodology §4a."
