#!/usr/bin/env bash
# The historical am3-s19kpro row is Unsupported. Its spelling is not an alias
# for the distinct Beta am3-s19k producer, which must be selected explicitly.
set -euo pipefail
echo "ERROR: am3-s19kpro is Unsupported; this historical capsule cannot publish Beta." >&2
echo "Use build_release_capsule.sh --producer am3-s19k only for that exact registered board." >&2
exit 2
