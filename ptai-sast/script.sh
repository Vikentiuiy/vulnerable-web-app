#!/usr/bin/env bash
# ptai-sast — wrapper around the PT Application Inspector CLI (ptai-cli-plugin.jar).
# Scan a code archive with a JSON scan config and get a SARIF report, plus a few
# helper commands. See:  ./script.sh help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$SCRIPT_DIR/ptai-cli-plugin.jar"

# ---- defaults (overridable by env or flags) ----
PTAI_URL="${PTAI_URL:-https://ptaiserver.ptai.local}"
PTAI_TOKEN="${PTAI_TOKEN:-}"
PTAI_HOST_IP="${PTAI_HOST_IP:-192.168.1.105}"   # for the docker runner's --add-host
PTAI_IMAGE="${PTAI_IMAGE:-ptai-cli:local}"
RUNNER="${PTAI_RUNNER:-auto}"                   # auto | java | docker

ARCHIVE="" ; CONFIG="" ; POLICY="" ; OUT="" ; EXCLUDES="" ; INCLUDES=""
BRANCH="" ; PROJECT="" ; REPORT_TEMPLATE="" ; REPORT_FILE="" ; INSECURE=1

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; RST=$'\e[0m'
die(){ echo "${RED}error:${RST} $*" >&2; exit 1; }

usage() {
cat <<EOF
${GRN}ptai-sast${RST} — PT Application Inspector CLI wrapper

${YEL}USAGE${RST}
  ./script.sh [command] [options]
  ./script.sh -archive code_archive.zip -config config.json      ${DIM}# 'scan' is the default${RST}

${YEL}COMMANDS${RST}
  scan        Scan a code archive/folder with a JSON config -> SARIF report  (default)
  check       Check the PT AI server connection and license
  templates   List the report templates available on the server
  report      Generate an HTML/PDF report for a scanned project
  help        Show this help

${YEL}OPTIONS${RST}
  -archive <path>     ${DIM}(scan)${RST} .zip archive OR a source folder to scan          ${RED}required for scan${RST}
  -config  <path>     ${DIM}(scan)${RST} JSON scan settings (.aiproj)                     ${RED}required for scan${RST}
  -policy  <path>     ${DIM}(scan)${RST} JSON AST policy (optional)
  -out     <path>     ${DIM}(scan)${RST} output SARIF file            (default: ./<archive>-result.sarif)
  -excludes <globs>   ${DIM}(scan)${RST} comma-separated Ant globs to exclude, e.g. '**/harness/**,**/exploits/**'
  -includes <globs>   ${DIM}(scan)${RST} comma-separated Ant globs to include
  -branch  <name>     ${DIM}(scan)${RST} PT AI branch name (default: default)
  -project <name>     ${DIM}(report)${RST} project name to report on
  -template <name>    ${DIM}(report)${RST} report template name
  -report-file <path> ${DIM}(report)${RST} output report file

  -url    <url>       PT AI server URL          (env PTAI_URL, default $PTAI_URL)
  -token  <token>     PT AI API token           (env PTAI_TOKEN)                    ${RED}required${RST}
  -runner <auto|java|docker>   how to run the jar (default auto: local java, else docker image)
  -no-insecure        verify TLS (default: -k / trust the lab cert)
  -h, --help          show this help

${YEL}ENVIRONMENT${RST}
  PTAI_URL, PTAI_TOKEN, PTAI_HOST_IP, PTAI_IMAGE, PTAI_RUNNER

${YEL}EXAMPLES${RST}
  export PTAI_TOKEN=xxxxx
  ./script.sh -archive code_archive.zip -config config.json
  ./script.sh scan -archive ./src -config config.json -out result.sarif -excludes '**/test/**'
  ./script.sh check -url https://ptaiserver.ptai.local
  ./script.sh templates
  ./script.sh report -project MyProject -template "OWASP Top 10 2021" -report-file report.html
EOF
}

# ---- decide runner ----
pick_runner() {
  if [ "$RUNNER" = "java" ]; then command -v java >/dev/null || die "java not found"; return; fi
  if [ "$RUNNER" = "docker" ]; then command -v docker >/dev/null || die "docker not found"; return; fi
  # auto
  if command -v java >/dev/null 2>&1; then RUNNER=java
  elif command -v docker >/dev/null 2>&1 && docker image inspect "$PTAI_IMAGE" >/dev/null 2>&1; then RUNNER=docker
  else die "need either 'java' or the docker image '$PTAI_IMAGE'"; fi
}

# ---- run the CLI: run_cli <extra-host-mounts...> -- <cli args...> ----
# Builds a java or docker invocation. Files are referenced by absolute host path
# for java; for docker they are mounted read-only and rewritten to /in/<name>.
run_cli() {
  local args=("$@")
  if [ "$RUNNER" = "java" ]; then
    java -jar "$JAR" "${args[@]}"
  else
    # docker: mount the dirs of any *.aiproj/.json/.zip/folder args and the output dir
    local mounts=() ; local a
    for a in "${args[@]}"; do
      if [ -e "$a" ]; then mounts+=( -v "$(cd "$(dirname "$a")" && pwd):$(cd "$(dirname "$a")" && pwd):ro" ); fi
    done
    [ -n "$OUT" ] && mounts+=( -v "$(cd "$(dirname "$OUT")" && pwd):$(cd "$(dirname "$OUT")" && pwd)" )
    docker run --rm --add-host "$(echo "$PTAI_URL" | sed -E 's#https?://([^/:]+).*#\1#'):$PTAI_HOST_IP" \
      "${mounts[@]}" "$PTAI_IMAGE" ptai-cli-plugin "${args[@]}"
  fi
}

cmd_scan() {
  [ -n "$ARCHIVE" ] || die "scan needs -archive <zip|folder>"
  [ -n "$CONFIG" ]  || die "scan needs -config <config.json>"
  [ -n "$PTAI_TOKEN" ] || die "no token (set PTAI_TOKEN or -token)"
  [ -e "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
  [ -e "$CONFIG" ]  || die "config not found: $CONFIG"

  # If given a .zip, unzip to a temp dir so the CLI scans the code (not a zip-of-zip).
  local input="$ARCHIVE" tmp=""
  if [ -f "$ARCHIVE" ] && [[ "$ARCHIVE" == *.zip ]]; then
    command -v unzip >/dev/null || die "unzip needed to expand $ARCHIVE"
    tmp="$(mktemp -d)"; unzip -q "$ARCHIVE" -d "$tmp"; input="$tmp"
    echo "${DIM}unzipped $ARCHIVE -> $input${RST}"
  fi
  [ -z "$OUT" ] && OUT="./$(basename "${ARCHIVE%.*}")-result.sarif"
  # make OUT absolute and split into dir + name: the CLI writes --sarif-report-file
  # relative to --output, so point --output at the desired directory.
  mkdir -p "$(dirname "$OUT")"
  OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
  local OUTDIR OUTBASE; OUTDIR="$(dirname "$OUT")"; OUTBASE="$(basename "$OUT")"

  local args=( json-ast --url "$PTAI_URL" --token "$PTAI_TOKEN"
               --settings-json "$CONFIG" --input "$input"
               --output "$OUTDIR" --sarif-report-file "$OUTBASE" )
  [ -n "$POLICY" ]   && args+=( --policy-json "$POLICY" )
  [ -n "$EXCLUDES" ] && args+=( --excludes "$EXCLUDES" )
  [ -n "$INCLUDES" ] && args+=( --includes "$INCLUDES" )
  [ -n "$BRANCH" ]   && args+=( --branch-name "$BRANCH" )
  [ "$INSECURE" = 1 ] && args+=( --insecure )

  echo "${GRN}>> scanning${RST} $ARCHIVE  (config: $(basename "$CONFIG"), runner: $RUNNER)"
  run_cli "${args[@]}" 2>&1 | grep -viE 'WARNING: sun.reflect|getCallerClass|restricted method|Restricted methods|loadLibrary|native-access|native access' || true
  [ -n "$tmp" ] && rm -rf "$tmp"
  if [ -f "$OUT" ]; then
    local n; n=$(python3 -c "import json,sys;print(sum(len(r.get('results',[])) for r in json.load(open('$OUT'))['runs']))" 2>/dev/null || echo "?")
    echo "${GRN}>> SARIF:${RST} $OUT  (${n} findings)"
  else
    die "no SARIF produced — check the settings/token/server"
  fi
}

cmd_check() {
  [ -n "$PTAI_TOKEN" ] || die "no token (set PTAI_TOKEN or -token)"
  local args=( check-server --url "$PTAI_URL" --token "$PTAI_TOKEN" ); [ "$INSECURE" = 1 ] && args+=( --insecure )
  run_cli "${args[@]}" 2>&1 | grep -viE 'WARNING: sun.reflect|getCallerClass|restricted method|Restricted methods|loadLibrary|native-access|native access'
}

cmd_templates() {
  [ -n "$PTAI_TOKEN" ] || die "no token (set PTAI_TOKEN or -token)"
  local args=( list-report-templates --url "$PTAI_URL" --token "$PTAI_TOKEN" ); [ "$INSECURE" = 1 ] && args+=( --insecure )
  run_cli "${args[@]}" 2>&1 | grep -viE 'WARNING: sun.reflect|getCallerClass|restricted method|Restricted methods|loadLibrary|native-access|native access'
}

cmd_report() {
  [ -n "$PTAI_TOKEN" ] || die "no token"; [ -n "$PROJECT" ] || die "report needs -project <name>"
  local args=( generate-report --url "$PTAI_URL" --token "$PTAI_TOKEN" --project "$PROJECT" )
  [ -n "$REPORT_TEMPLATE" ] && args+=( --report-template "$REPORT_TEMPLATE" )
  [ -n "$REPORT_FILE" ]     && args+=( --report-file "$REPORT_FILE" )
  [ "$INSECURE" = 1 ] && args+=( --insecure )
  run_cli "${args[@]}" 2>&1 | grep -viE 'WARNING: sun.reflect|getCallerClass|restricted method|Restricted methods|loadLibrary|native-access|native access'
}

# ---- parse: optional command, then flags (single- or double-dash) ----
CMD="scan"
case "${1:-}" in scan|check|templates|report) CMD="$1"; shift;; help|-h|--help) usage; exit 0;; esac
while [ $# -gt 0 ]; do
  case "$1" in
    -archive|--archive)   ARCHIVE="$2"; shift 2;;
    -config|--config)     CONFIG="$2"; shift 2;;
    -policy|--policy)     POLICY="$2"; shift 2;;
    -out|--out|-o)        OUT="$2"; shift 2;;
    -excludes|--excludes) EXCLUDES="$2"; shift 2;;
    -includes|--includes) INCLUDES="$2"; shift 2;;
    -branch|--branch)     BRANCH="$2"; shift 2;;
    -project|--project)   PROJECT="$2"; shift 2;;
    -template|--template) REPORT_TEMPLATE="$2"; shift 2;;
    -report-file|--report-file) REPORT_FILE="$2"; shift 2;;
    -url|--url)           PTAI_URL="$2"; shift 2;;
    -token|--token)       PTAI_TOKEN="$2"; shift 2;;
    -runner|--runner)     RUNNER="$2"; shift 2;;
    -no-insecure)         INSECURE=0; shift;;
    -h|--help)            usage; exit 0;;
    *) die "unknown option: $1  (see ./script.sh help)";;
  esac
done

[ -f "$JAR" ] || die "jar not found next to the script: $JAR"
pick_runner
case "$CMD" in
  scan)      cmd_scan;;
  check)     cmd_check;;
  templates) cmd_templates;;
  report)    cmd_report;;
esac
