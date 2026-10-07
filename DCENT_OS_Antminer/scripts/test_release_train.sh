#!/usr/bin/env bash
# Thin runner for test_release_train.py (repo convention: one test_X.sh per suite).
# python3 first (CI/WSL); fall back to the Windows launcher on Git Bash hosts
# where python3 is shadowed by the WindowsApps stub.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/test_release_train.py"
else
    py -3 "$SCRIPT_DIR/test_release_train.py"
fi
