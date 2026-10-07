#!/bin/sh
# Release-train adapter; inputs are explicit current build outputs.
set -eu
[ "$#" = 2 ] || { echo "Usage: $0 am1-s9i|am1-s9j|am1-s9se|am1-s9k|am1-s15|am1-t15 NEW_OUTPUT_DIR" >&2; exit 2; }
dcent_target=$1
dcent_output=$2
dcent_scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${DCENT_NATIVE_SD_ROOTFS:?set the current native userspace squashfs path}"
: "${DCENT_NATIVE_SD_BINARIES:?set the directory of the three current ARM binaries}"
dcent_guide=docs/guides/quickstart-native-am1-sd.md
case "$dcent_target" in
    am1-s15|am1-t15)
        : "${DCENT_BM1391_SD_DONOR:?set the exact target resident boot directory}"
        sh "$dcent_scripts/build_sd_bm1391.sh" "$dcent_target" "$DCENT_BM1391_SD_DONOR" \
            "$DCENT_NATIVE_SD_ROOTFS" "$DCENT_NATIVE_SD_BINARIES" "$dcent_output"
        dcent_guide=docs/BM1391_SD.md
        ;;
    am1-s9se|am1-s9k)
        sh "$dcent_scripts/build_sd_c43.sh" "$dcent_target" "$DCENT_NATIVE_SD_ROOTFS" "$DCENT_NATIVE_SD_BINARIES" "$dcent_output"
        ;;
    am1-s9i|am1-s9j)
        sh "$dcent_scripts/build_sd_s9_variant.sh" "$dcent_target" "$DCENT_NATIVE_SD_ROOTFS" "$dcent_output" "$DCENT_NATIVE_SD_BINARIES"
        ;;
    *) echo "Unknown exact native AM1 target" >&2; exit 2 ;;
esac
dcent_project=$(dirname -- "$dcent_scripts")
cp "$dcent_project/../dcent-toolbox/$dcent_guide" "$dcent_output/TESTER_README.txt"
