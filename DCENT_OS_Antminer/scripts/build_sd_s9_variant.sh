#!/bin/sh
# Compose an exact native S9i/S9j beta from a current S9 Buildroot squashfs.
# Host-only regular-file image assembly. No miner or block device access.
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $0 am1-s9i|am1-s9j CURRENT_S9_ROOTFS.squashfs NEW_OUTPUT_DIRECTORY [CURRENT_ARM_BINARY_DIR]" >&2
    exit 2
fi
board_target=$1
rootfs_input=$2
output_dir=$3
dcent_binary_dir=${4:-}
case "$board_target" in
    am1-s9i|am1-s9j) ;;
    *) echo "Unsupported exact BM1387 beta target: $board_target" >&2; exit 2 ;;
esac
[ -f "$rootfs_input" ] && [ ! -L "$rootfs_input" ] || {
    echo "Rootfs must be an existing regular squashfs file" >&2; exit 2;
}
[ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] || {
    echo "Output directory must be new: $output_dir" >&2; exit 2;
}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
firmware_dir=$(dirname -- "$script_dir")
policy="$firmware_dir/dcentrald/configs/beta/$board_target-experimental.toml"
config="$firmware_dir/dcentrald/configs/beta/$board_target-baked-default.toml"
for source in "$policy" "$config"; do
    [ -f "$source" ] && [ ! -L "$source" ] || { echo "Missing regular beta source: $source" >&2; exit 2; }
done
for tool in unsquashfs mksquashfs bash python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing host tool: $tool" >&2; exit 2; }
done
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-s9-variant.XXXXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
unsquashfs -processors 2 -no-progress -d "$work_dir/rootfs" "$rootfs_input"
# The input must be the actual S9 userspace. This guards cross-carrier input
# before installing variant identity; it is independent of runtime live checks.
[ -f "$work_dir/rootfs/etc/dcentos/board_target" ] &&
    [ "$(cat "$work_dir/rootfs/etc/dcentos/board_target")" = "am1-s9" ] || {
        echo "Input is not an exact AM1 S9 rootfs" >&2; exit 2;
    }
if [ -n "$dcent_binary_dir" ]; then
    python3 "$script_dir/prepare_s9_variant_rootfs.py" \
        --board-target "$board_target" --rootfs "$work_dir/rootfs" --binaries "$dcent_binary_dir"
else
    python3 "$script_dir/prepare_s9_variant_rootfs.py" \
        --board-target "$board_target" --rootfs "$work_dir/rootfs"
fi
mkdir "$work_dir/images"
mksquashfs "$work_dir/rootfs" "$work_dir/images/rootfs.squashfs" \
    -comp gzip -all-root -noappend -no-progress -processors 2
mkdir "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
DCENTOS_BUILDROOT_IMAGES="$work_dir/images" DCENTOS_SD_OUTPUT_DIR="$output_dir" \
    DCENTOS_S9_BOARD_TARGET="$board_target" \
    bash "$script_dir/build_sd_image.sh" --standalone --disk-image
cp "$work_dir/images/rootfs.squashfs" "$output_dir/rootfs.squashfs"
if [ -f "$work_dir/rootfs/etc/dcentos/native-runtime-inputs.json" ]; then
    cp "$work_dir/rootfs/etc/dcentos/native-runtime-inputs.json" "$output_dir/runtime-inputs.json"
fi
echo "Built $board_target native beta: $output_dir/dcentos-sd.img"
