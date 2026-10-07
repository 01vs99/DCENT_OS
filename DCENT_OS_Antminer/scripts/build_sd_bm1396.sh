#!/bin/sh
# Exact BM1396 media; output is a new regular file, never a block device.
set -eu
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 {am2-t17e|am2-s17e} PINNED_RESIDENT_BOOT_DIR CURRENT_ARM_ROOTFS.squashfs CURRENT_ARM_BINARY_DIR NEW_OUTPUT_DIR" >&2
    exit 2
fi
dcent_target=$1 dcent_donor=$2 dcent_rootfs=$3 dcent_binaries=$4 dcent_output=$5
case "$dcent_target" in am2-t17e) dcent_model=T17e ;; am2-s17e) dcent_model=S17e ;; *) exit 2 ;; esac
[ -f "$dcent_rootfs" ] && [ ! -L "$dcent_rootfs" ] || exit 2
[ -d "$dcent_donor" ] && [ ! -L "$dcent_donor" ] || exit 2
[ -d "$dcent_binaries" ] && [ ! -L "$dcent_binaries" ] || exit 2
[ ! -e "$dcent_output" ] && [ ! -L "$dcent_output" ] || exit 2
[ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ] && [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ] || {
    echo "$dcent_model beta image requires explicit runtime signing key and trusted public key" >&2; exit 2;
}
for dcent_tool in python3 unsquashfs mkimage fdtput mkfs.vfat mcopy mke2fs truncate sha256sum debugfs e2fsck; do
    command -v "$dcent_tool" >/dev/null 2>&1 || { echo "Missing host tool: $dcent_tool" >&2; exit 2; }
done
dcent_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Retain failed staging for diagnosis. Only remove the resolved mktemp root
# after successful composition; no device paths are accepted by the producer.
dcent_work=$(mktemp -d /tmp/dcentos-bm1396.XXXXXXXX)
echo "BM1396 private root staging: $dcent_work"
/usr/bin/unsquashfs -processors 2 -no-progress -d "$dcent_work/rootfs" "$dcent_rootfs"
# Inside Buildroot make the host toolchain's minimal python3 shadows the
# container system python; the prepare_bm1396_* scripts need the system
# python's site packages (python3-cryptography). Pin the interpreter.
dcent_root_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4())')
dcent_data_uuid=$(/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" data-uuid --target "$dcent_target")
dcent_base_sha=$(sha256sum "$dcent_rootfs" | awk '{print $1}')
/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" root --root "$dcent_work/rootfs" \
    --target "$dcent_target" --binaries "$dcent_binaries" \
    --root-uuid "$dcent_root_uuid" --data-uuid "$dcent_data_uuid" --base-sha256 "$dcent_base_sha"
/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_boot.py" --output "$dcent_output" --donor "$dcent_donor" --target "$dcent_target"
dcent_output=$(CDPATH= cd -- "$dcent_output" && pwd)
truncate -s 134217728 "$dcent_output/rootfs.ext2"
/usr/sbin/mke2fs -q -F -t ext2 -b 4096 -U "$dcent_root_uuid" -L DCENT_BM1396_RT \
    -O 'none,ext_attr,resize_inode,dir_index,filetype,sparse_super,large_file' \
    -d "$dcent_work/rootfs" "$dcent_output/rootfs.ext2"
# Preserve allocated protected ELF pages for the independent ext2 reader.
for dcent_binary in usr/local/bin/dcentrald sbin/init usr/bin/dcentos-discovery; do
    dcent_size=$(wc -c < "$dcent_work/rootfs/$dcent_binary")
    /usr/sbin/debugfs -w -R "fallocate /$dcent_binary 0 $(((dcent_size - 1) / 4096))" "$dcent_output/rootfs.ext2"
done
/usr/sbin/e2fsck -f -n "$dcent_output/rootfs.ext2"
truncate -s 67108864 "$dcent_output/data.ext4"
/usr/sbin/mke2fs -q -F -t ext4 -b 4096 -U "$dcent_data_uuid" -L DCENT_BM1396_DT \
    -O 'none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,flex_bg,sparse_super,large_file,uninit_bg,dir_nlink,extra_isize' \
    -E lazy_itable_init=0,lazy_journal_init=0 "$dcent_output/data.ext4"
/usr/sbin/mkfs.vfat -F 32 -n DCENT1396 -C "$dcent_output/boot.vfat" 65536
for dcent_file in BOOT.BIN uImage devicetree.dtb bm1396-fabric.itb bm1396-system.bin uEnv.txt; do
    /usr/bin/mcopy -i "$dcent_output/boot.vfat" "$dcent_output/$dcent_file" ::/
done
dcent_version=$(cat "$dcent_work/rootfs/etc/dcentos-version")
/usr/bin/python3 "$dcent_script_dir/prepare_bm1396_sd_image.py" assemble --output "$dcent_output" --target "$dcent_target" --version "$dcent_version"
cp "$dcent_work/rootfs/etc/dcentos/bm1396-runtime-inputs.json" "$dcent_output/runtime-inputs.json"
cat > "$dcent_output/TESTER_README.txt" <<README
DCENTos $dcent_model native SD beta: removable media must remain inserted.
Mining is off by default. Verify the signed artifact and runtime companions.
The image performs no NAND installation. Remove the card to return to NAND.
Physical quiet-policy airflow, hashing and recovery remain bench qualification.
Support development: https://d-central.tech/fund/
README
case "$dcent_work" in /tmp/dcentos-bm1396.????????) rm -rf -- "$dcent_work" ;; *) exit 3 ;; esac
echo "Built $dcent_target native SD candidate: $dcent_output/dcentos-sd.img"
echo "Dashboard setup and provisioned SSH; remove the card to return to the existing NAND installation."
