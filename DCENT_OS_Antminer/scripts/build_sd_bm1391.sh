#!/bin/sh
# Exact BM1391 media; output is a new regular file, never a block device.
set -eu
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 am1-s15|am1-t15 PINNED_RESIDENT_BOOT_DIR CURRENT_ARM_ROOTFS.squashfs CURRENT_ARM_BINARY_DIR NEW_OUTPUT_DIR" >&2
    exit 2
fi
dcent_target=$1 dcent_donor=$2 dcent_rootfs=$3 dcent_binaries=$4 dcent_output=$5
case "$dcent_target" in am1-s15|am1-t15) ;; *) exit 2 ;; esac
[ -f "$dcent_rootfs" ] && [ ! -L "$dcent_rootfs" ] || exit 2
[ -d "$dcent_donor" ] && [ ! -L "$dcent_donor" ] || exit 2
[ -d "$dcent_binaries" ] && [ ! -L "$dcent_binaries" ] || exit 2
[ ! -e "$dcent_output" ] && [ ! -L "$dcent_output" ] || exit 2
for dcent_tool in python3 unsquashfs mkimage fdtput mkfs.vfat mcopy mke2fs truncate sha256sum; do
    command -v "$dcent_tool" >/dev/null 2>&1 || { echo "Missing host tool: $dcent_tool" >&2; exit 2; }
done
dcent_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Retain failed staging for diagnosis. Only remove the resolved mktemp root
# after successful composition; no device paths are accepted by the producer.
dcent_work=$(mktemp -d /tmp/dcentos-bm1391.XXXXXXXX)
echo "BM1391 private root staging: $dcent_work"
unsquashfs -processors 2 -no-progress -d "$dcent_work/rootfs" "$dcent_rootfs"
dcent_root_uuid=$(python3 -c 'import uuid; print(uuid.uuid4())')
dcent_data_uuid=$(python3 "$dcent_script_dir/prepare_bm1391_sd_image.py" data-uuid --target "$dcent_target")
dcent_base_sha=$(sha256sum "$dcent_rootfs" | awk '{print $1}')
python3 "$dcent_script_dir/prepare_bm1391_sd_image.py" root --root "$dcent_work/rootfs" \
    --target "$dcent_target" --binaries "$dcent_binaries" \
    --root-uuid "$dcent_root_uuid" --data-uuid "$dcent_data_uuid" --base-sha256 "$dcent_base_sha"
python3 "$dcent_script_dir/prepare_bm1391_sd_boot.py" --output "$dcent_output" --donor "$dcent_donor" --target "$dcent_target"
dcent_output=$(CDPATH= cd -- "$dcent_output" && pwd)
truncate -s 134217728 "$dcent_output/rootfs.ext2"
mke2fs -q -F -t ext2 -b 4096 -U "$dcent_root_uuid" -L DCENT_BM1391_RT \
    -O 'none,ext_attr,resize_inode,dir_index,filetype,sparse_super,large_file' \
    -d "$dcent_work/rootfs" "$dcent_output/rootfs.ext2"
truncate -s 67108864 "$dcent_output/data.ext4"
mke2fs -q -F -t ext4 -b 4096 -U "$dcent_data_uuid" -L DCENT_BM1391_DT \
    -O 'none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,uninit_bg,dir_nlink,extra_isize' \
    "$dcent_output/data.ext4"
mkfs.vfat -F 32 -n DCENT1391 -C "$dcent_output/boot.vfat" 65536
for dcent_file in BOOT.BIN uImage devicetree.dtb bm1391-fabric.itb bm1391-system.bin uEnv.txt; do
    mcopy -i "$dcent_output/boot.vfat" "$dcent_output/$dcent_file" ::/
done
python3 "$dcent_script_dir/prepare_bm1391_sd_image.py" assemble --output "$dcent_output" --target "$dcent_target"
cp "$dcent_work/rootfs/etc/dcentos/bm1391-runtime-inputs.json" "$dcent_output/runtime-inputs.json"
case "$dcent_work" in /tmp/dcentos-bm1391.????????) rm -rf -- "$dcent_work" ;; *) exit 3 ;; esac
echo "Built $dcent_target native SD candidate: $dcent_output/dcentos-sd.img"
echo "Dashboard setup and provisioned SSH; remove the card to return to the existing NAND installation."
