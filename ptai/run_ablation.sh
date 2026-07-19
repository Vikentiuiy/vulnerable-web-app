#!/usr/bin/env bash
# Run all scan profiles for a target and compare module contributions.
# Usage: PTAI_TOKEN=... ptai/run_ablation.sh <target-dir>
set -euo pipefail
TARGET="${1:?usage: run_ablation.sh <target-dir>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
NAME="$(basename "$TARGET")"
for P in default pm config max; do
  [ -f "$TARGET/profiles/$P.aiproj" ] && ptai/scan.sh "$TARGET" "$P" "results/$NAME-$P.sarif"
done
echo "=== per-profile score vs reference ==="
for P in default pm config max; do
  f="results/$NAME-$P.sarif"; [ -f "$f" ] && { printf '%-8s ' "$P"; python3 checker/sast_checker.py -r "$TARGET/reference.sarif" -a "$f" --quiet; }
done
echo "=== module contribution matrix ==="
python3 ptai/compare_profiles.py results/$NAME-default.sarif results/$NAME-pm.sarif results/$NAME-config.sarif results/$NAME-max.sarif
