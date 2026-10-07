#!/bin/sh
# Exact-target wrapper for the shared 17-family builder.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$SCRIPT_DIR/../post-image-17-family.sh" --board-target am2-s17p "$@"
