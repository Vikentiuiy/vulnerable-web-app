#!/usr/bin/env bash
# Compare two SAST tools on one target against the shared reference: engine
# (taint-class) recall + precision, tool-agnostic (works on any SARIF).
#   ptai/compare_tools.sh <target> <ptai.sarif> <oss.sarif> [oss-name]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
T="$1"; A="$2"; B="$3"; BN="${4:-oss}"
REF="targets/$T/reference.sarif"

row() {
  local name="$1" sarif="$2"
  [ -f "$sarif" ] || { printf "  %-10s %s\n" "$name" "(missing)"; return; }
  local rep; rep="$(python3 checker/sast_checker.py -r "$REF" -a "$sarif" 2>/dev/null || true)"
  local taint prec fp
  taint="$(echo "$rep" | grep 'taint' | head -1 | grep -oE '[0-9]+/[0-9]+ *= *[0-9.]+%' | tr -s ' ')"
  prec="$(echo "$rep" | grep -E '^ Precision ' | head -1 | grep -oE '[0-9.]+%' | head -1)"
  fp="$(echo "$rep" | grep -E '^ False positives' | grep -oE '[0-9]+' | head -1)"
  printf "  %-10s taint=%-14s precision=%-8s FP=%s\n" "$name" "${taint:-n/a}" "${prec:-n/a}" "${fp:-?}"
}

echo "== $T : PT AI vs $BN (engine, shared reference) =="
row "PT-AI" "$A"
row "$BN" "$B"
