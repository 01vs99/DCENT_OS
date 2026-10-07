#!/bin/sh
# Final host-side native overlay/signing after the base Buildroot post-build.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${DCENT_NATIVE_SD_TARGET:?exact native SD target required}"
: "${DCENT_NATIVE_SD_BINARIES:?current native executable directory required}"
# Buildroot puts its minimal host interpreter first on PATH inside make;
# release_native_sd.py needs the container system python's site packages
# (python3-cryptography). Pin the system interpreter explicitly.
exec /usr/bin/python3 "$here/release_native_sd.py" prepare-root --rootfs "${1:?Buildroot target required}" \
    --board-target "$DCENT_NATIVE_SD_TARGET" --binaries "$DCENT_NATIVE_SD_BINARIES"
