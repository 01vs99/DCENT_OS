#!/bin/sh
# Buildroot native release media assembly using staged, exact pinned boot files.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${DCENT_NATIVE_SD_TARGET:?exact native SD target required}"
: "${DCENT_NATIVE_SD_BOOT_INPUTS:?staged exact boot inputs required}"
# Inside Buildroot make the host toolchain's minimal python3 shadows the
# container system python; release_native_sd.py needs the system python's
# site packages (python3-cryptography). Pin the system interpreter.
exec /usr/bin/python3 "$here/release_native_sd.py" assemble --rootfs "${TARGET_DIR:?Buildroot target required}" \
    --images "${BINARIES_DIR:-${1:?Buildroot images required}}" \
    --board-target "$DCENT_NATIVE_SD_TARGET" --boot-inputs "$DCENT_NATIVE_SD_BOOT_INPUTS"
