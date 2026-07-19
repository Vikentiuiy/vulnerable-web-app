#!/usr/bin/env bash
# Drive a PT Application Inspector scan of one target with one scan profile and
# emit SARIF. Wraps the official ptai-cli-plugin (image ptai-cli:local).
#
# Usage:
#   PTAI_TOKEN=... ptai/scan.sh <target-dir> <profile> [out.sarif]
# Example:
#   PTAI_TOKEN=xxx ptai/scan.sh targets/java-web default results/java-web-default.sarif
#
# Env:
#   PTAI_TOKEN   (required) PT AI API token (Access-Token flow)
#   PTAI_URL     (default https://ptaiserver.ptai.local)
#   PTAI_HOST    (default ptaiserver.ptai.local)
#   PTAI_HOST_IP (default 192.168.1.105)  -> added via --add-host for DNS
#   PTAI_IMAGE   (default ptai-cli:local)
set -euo pipefail

TARGET="${1:?usage: scan.sh <target-dir> <profile> [out.sarif]}"
PROFILE="${2:?usage: scan.sh <target-dir> <profile> [out.sarif]}"
OUT="${3:-results/$(basename "$TARGET")-$PROFILE.sarif}"

: "${PTAI_TOKEN:?set PTAI_TOKEN}"
PTAI_URL="${PTAI_URL:-https://ptaiserver.ptai.local}"
PTAI_HOST="${PTAI_HOST:-ptaiserver.ptai.local}"
PTAI_HOST_IP="${PTAI_HOST_IP:-192.168.1.105}"
PTAI_IMAGE="${PTAI_IMAGE:-ptai-cli:local}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_ABS="$(cd "$ROOT/$TARGET" 2>/dev/null || cd "$TARGET"; pwd)"
AIPROJ="$TARGET_ABS/profiles/$PROFILE.aiproj"
SRC="$TARGET_ABS/src"
[ -d "$SRC" ] || SRC="$TARGET_ABS"          # targets without src/ scan the whole dir
[ -f "$AIPROJ" ] || { echo "no profile: $AIPROJ" >&2; exit 2; }

# Build --excludes from scope.txt (Ant globs, one per line, # comments) if present.
EXCLUDES=""
SCOPE="$TARGET_ABS/scope.txt"
if [ -f "$SCOPE" ]; then
  EXCLUDES="$(grep -vE '^\s*(#|$)' "$SCOPE" | grep -E '^\s*-' | sed -E 's/^\s*-\s*//' | paste -sd, -)"
fi

OUT_ABS="$ROOT/$OUT"; mkdir -p "$(dirname "$OUT_ABS")"
OUT_DIR="$(dirname "$OUT_ABS")"; OUT_FILE="$(basename "$OUT_ABS")"

echo ">> scan target=$TARGET profile=$PROFILE excludes='${EXCLUDES:-<none>}'"
docker run --rm --add-host "$PTAI_HOST:$PTAI_HOST_IP" \
  -v "$SRC":/work/src:ro \
  -v "$AIPROJ":/work/s.aiproj:ro \
  -v "$OUT_DIR":/work/out \
  "$PTAI_IMAGE" ptai-cli-plugin json-ast \
    --url "$PTAI_URL" --token "$PTAI_TOKEN" \
    --settings-json /work/s.aiproj --input /work/src --output /work/out \
    --sarif-report-file "/work/out/$OUT_FILE" \
    ${EXCLUDES:+--excludes "$EXCLUDES"} \
    --insecure 2>&1 | grep -viE 'WARNING: sun.reflect' || true

[ -f "$OUT_ABS" ] && echo ">> SARIF: $OUT ($(python3 -c "import json;print(sum(len(r.get('results',[])) for r in json.load(open('$OUT_ABS'))['runs']))") findings)"
