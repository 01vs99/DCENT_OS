#!/usr/bin/env bash
# Compatibility entry point; current producer contract owns all build decisions.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${DCENT_RELEASE_TARGET:-s9}" in
    s9|am2-s19jpro) ;;
    *) echo "ERROR: select an exact producer with build_release_capsule.sh" >&2; exit 2 ;;
esac
exec bash "$SCRIPT_DIR/build_release_capsule.sh" --producer "${DCENT_RELEASE_TARGET:-s9}" "$@"
