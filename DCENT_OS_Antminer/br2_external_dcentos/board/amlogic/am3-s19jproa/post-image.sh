#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$SCRIPT_DIR/../am3-bm1362-nopic/post-image.sh" "$@"
