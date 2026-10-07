#!/bin/sh
# Buildroot-only host file finalization; no image/media/device operation.
set -eu
[ "$#" -eq 2 ] || { echo "native SD post-build requires target and input manifest" >&2; exit 2; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$here/finalize_root.py" "$1" "$2"
