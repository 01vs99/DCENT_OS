#!/bin/sh
# Build exact C43 media from current native userspace and current ARM binaries.
# All outputs are regular files in a new directory; no device or miner access.
set -eu
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 am1-s9se|am1-s9k CURRENT_ARM_ROOTFS.squashfs CURRENT_ARM_BINARY_DIR NEW_OUTPUT_DIR" >&2
    exit 2
fi
dcent_target=$1
dcent_rootfs=$2
dcent_binaries=$3
dcent_output=$4
case "$dcent_target" in am1-s9se|am1-s9k) ;; *) exit 2 ;; esac
[ -f "$dcent_rootfs" ] && [ ! -L "$dcent_rootfs" ] || exit 2
[ -d "$dcent_binaries" ] && [ ! -L "$dcent_binaries" ] || exit 2
[ ! -e "$dcent_output" ] && [ ! -L "$dcent_output" ] || exit 2
for dcent_tool in python3 unsquashfs mkimage fdtput mkfs.vfat mcopy mke2fs truncate sha256sum; do
    command -v "$dcent_tool" >/dev/null 2>&1 || { echo "Missing host tool: $dcent_tool" >&2; exit 2; }
done
dcent_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dcent_work=$(mktemp -d "${TMPDIR:-/tmp}/dcentos-c43.XXXXXXXX")
trap 'rm -rf -- "$dcent_work"' EXIT HUP INT TERM
unsquashfs -processors 2 -no-progress -d "$dcent_work/rootfs" "$dcent_rootfs"
dcent_root_uuid=$(python3 -c 'import uuid; print(uuid.uuid4())')
dcent_data_uuid=$(python3 "$dcent_script_dir/prepare_c43_sd_image.py" data-uuid --target "$dcent_target")
dcent_base_sha=$(sha256sum "$dcent_rootfs" | awk '{print $1}')
python3 "$dcent_script_dir/prepare_c43_sd_image.py" root --root "$dcent_work/rootfs" \
    --target "$dcent_target" --binaries "$dcent_binaries" \
    --root-uuid "$dcent_root_uuid" --data-uuid "$dcent_data_uuid" --base-sha256 "$dcent_base_sha"
mkdir "$dcent_output"
dcent_output=$(CDPATH= cd -- "$dcent_output" && pwd)
python3 "$dcent_script_dir/prepare_c43_sd_image.py" boot --output "$dcent_output"
truncate -s 134217728 "$dcent_output/rootfs.ext2"
mke2fs -q -F -t ext2 -b 4096 -U "$dcent_root_uuid" -L DCENT_C43_ROOT \
    -O 'none,ext_attr,resize_inode,dir_index,filetype,sparse_super,large_file' \
    -d "$dcent_work/rootfs" "$dcent_output/rootfs.ext2"
truncate -s 67108864 "$dcent_output/data.ext4"
mke2fs -q -F -t ext4 -b 4096 -U "$dcent_data_uuid" -L DCENT_C43_DATA \
    -O 'none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,uninit_bg,dir_nlink,extra_isize' \
    "$dcent_output/data.ext4"
mkfs.vfat -F 32 -n DCENT_C43 -C "$dcent_output/boot.vfat" 65536
for dcent_file in BOOT.BIN uImage devicetree.dtb c43-fabric.itb c43-system.bin uEnv.txt; do
    mcopy -i "$dcent_output/boot.vfat" "$dcent_output/$dcent_file" ::/
done
python3 "$dcent_script_dir/prepare_c43_sd_image.py" assemble --output "$dcent_output" --target "$dcent_target"
cp "$dcent_work/rootfs/etc/dcentos/c43-runtime-inputs.json" "$dcent_output/runtime-inputs.json"
echo "Built $dcent_target native SD beta: $dcent_output/dcentos-sd.img"
echo "Dashboard setup and provisioned SSH; remove the card to return to the existing NAND installation."
