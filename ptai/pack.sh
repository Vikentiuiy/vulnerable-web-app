#!/usr/bin/env bash
# Build a clean SAST-upload archive for ONE target: only the in-scope vulnerable
# code, with the harness / exploits / build output / deps stripped out (per the
# target's scope.txt). This is what you upload to a SAST — NOT the whole repo.
#
#   ptai/pack.sh <target-dir> [out.zip]
#   ptai/pack.sh targets/java-web
set -euo pipefail

TARGET="${1:?usage: pack.sh <target-dir> [out.zip]}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
TARGET="${TARGET%/}"
NAME="$(basename "$TARGET")"
OUT="${2:-dist/${NAME}-scan.zip}"

# Source root actually scanned: src/ or Sources/ (Swift) or the target dir itself.
SRC="$TARGET/src"
[ -d "$SRC" ] || SRC="$TARGET/Sources"
[ -d "$SRC" ] || SRC="$TARGET"

# Always-strip: harness (instrumentation), exploits, tooling, build output, deps, vcs.
EXCLUDES=(--exclude=harness --exclude=exploits --exclude=tools --exclude=profiles
          --exclude=.git --exclude=target --exclude=build --exclude=.build
          --exclude=dist --exclude=node_modules --exclude=__pycache__
          --exclude='*.pyc' --exclude=reference.sarif --exclude=scope.txt
          --exclude='results' )
# Plus any directory named in scope.txt excludes (e.g. **/foo/**).
if [ -f "$TARGET/scope.txt" ]; then
  while IFS= read -r line; do
    d="$(echo "$line" | sed -nE 's#^- +\*\*/([A-Za-z0-9_.-]+)/\*\*$#\1#p')"
    [ -n "$d" ] && EXCLUDES+=(--exclude="$d")
    f="$(echo "$line" | sed -nE 's#^- +\*\*/([A-Za-z0-9_.-]+)$#\1#p')"
    [ -n "$f" ] && EXCLUDES+=(--exclude="$f")
  done < "$TARGET/scope.txt"
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
rsync -a "${EXCLUDES[@]}" "$SRC"/ "$TMP/$NAME/" 2>/dev/null

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$TMP" && zip -rq "$OLDPWD/$OUT" "$NAME" )

echo "== packed SAST archive: $OUT =="
echo "   source root : $SRC"
echo "   files       : $(find "$TMP/$NAME" -type f | wc -l)"
echo "   size        : $(du -h "$OUT" | cut -f1)"
echo "   contents:"
( cd "$TMP" && find "$NAME" -type f | sort | sed 's/^/     /' | head -60 )
echo "   (harness / exploits / build / deps excluded — safe to upload)"
