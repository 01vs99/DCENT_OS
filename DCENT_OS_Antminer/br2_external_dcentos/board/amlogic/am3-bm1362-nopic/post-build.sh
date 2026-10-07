#!/bin/sh
# Exact A126/Plus120 startup prerequisites. No physical or install admission.
set -eu
TARGET_DIR=$1
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
TARGET=$(cat "$TARGET_DIR/etc/dcentos/board_target")
case "$TARGET" in am3-s19jproa|am3-s19jproplus) ;; *) echo "ERROR: exact A126/Plus120 target required" >&2; exit 1 ;; esac
for required in etc/dcentos-early-init.sh etc/init.d/S45persistent \
    usr/libexec/dcentos/bm1362-nopic-storage.py usr/sbin/ubiattach; do
    [ -f "$TARGET_DIR/$required" ] && [ ! -L "$TARGET_DIR/$required" ] || {
        echo "ERROR: required A126/Plus120 startup file missing/indirect: $required" >&2
        exit 1
    }
    chmod 0755 "$TARGET_DIR/$required"
done
exec "$SCRIPT_DIR/../am3-s21/post-build.sh" "$@"
