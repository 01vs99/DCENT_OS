#!/bin/sh
# Exact S17e/T17e composition from the freshly signed Buildroot carrier.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "${DCENT_NATIVE_SD_TARGET:-}" in
    am2-s17e|am2-t17e) ;;
    *) echo 'ERROR: exact S17e/T17e release target required' >&2; exit 2 ;;
esac
: "${DCENT_NATIVE_SD_BOOT_INPUTS:?staged exact selected BM1396 boot inputs required}"
: "${DCENT_NATIVE_SD_BINARIES:?current ARM executables required}"
: "${DCENT_RELEASE_DASHBOARD_DIR:?sealed dashboard required}"
images=${BINARIES_DIR:-${1:?Buildroot images required}}
[ -d "$images" ] && [ ! -L "$images" ] || exit 2
candidate="$images/dcent-bm1396-media"
sh "$here/build_sd_bm1396.sh" "$DCENT_NATIVE_SD_TARGET" "$DCENT_NATIVE_SD_BOOT_INPUTS" \
    "$images/rootfs.squashfs" "$DCENT_NATIVE_SD_BINARIES" "$candidate"
for name in dcentos-sd.img dcentos-sd.img.manifest.json dcentos-sd.img.runtime-image.json dcentos-sd.img.runtime-image.sig TESTER_README.txt; do
    [ ! -e "$images/$name" ] && [ ! -L "$images/$name" ] || {
        echo "ERROR: BM1396 release destination already exists: $name" >&2; exit 2;
    }
    [ -f "$candidate/$name" ] && [ ! -L "$candidate/$name" ] || exit 2
    cp "$candidate/$name" "$images/$name"
done
