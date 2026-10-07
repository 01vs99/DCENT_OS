#!/bin/sh
# Exact-target wrapper; all package construction lives in the shared builder.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$SCRIPT_DIR/../post-image-family.sh" --board-target am3-t21 "$@"
