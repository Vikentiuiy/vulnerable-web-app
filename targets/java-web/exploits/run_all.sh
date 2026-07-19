#!/usr/bin/env bash
# Convenience wrapper: install deps and run the full PoC exploit suite.
set -e
cd "$(dirname "$0")/.."
python3 -m pip install -q -r poc/requirements.txt 2>/dev/null || true
python3 poc/exploit_all.py "$@"
