#!/bin/bash
#
# build_sd_s19pro.sh — Build DCENT_OS lab SD boot media for the AM2 Zynq family
# (S19 Pro, S17 / S17 Pro, and — since the 2026-08-27 unlock armada — S17+,
# T17, T17+; all BM1397 17-series SKUs ride the same held Braiins am2-s17
# boot components per A2 section 3).
# D-Central Technologies, 2026
#
# Creates a bootable SD card for AM2 lab bring-up and SD boot validation.
# It does NOT imply a safe public NAND install path for any miner variant.
# Uses BraiinsOS boot chain (FSBL, U-Boot, FPGA, kernel) + DCENT_OS rootfs.
#
# SD-TRIAL CONTRACT (17 family): zero NAND writes. On a stock unit the stock
# NAND u-boot chain-loads the SD payload (uenvcmd, see the uEnv notes); the
# `boot_stock` flag file on the FAT is the documented escape back to the
# stock chain. Held boot assets are referenced by exact path + SHA256 below
# and are NEVER regenerated.
#
# *** 2026-06-10 SD BOOT DEFECT FIX (squashfs-root model) ***
# The previous revision booted the squashfs as a U-Boot ramdisk
# (root=/dev/ram0 ramdisk_size=64M rootfstype=squashfs + uInitrd) — an
# UNPROVEN model that additionally depends on CONFIG_BLK_DEV_RAM in the
# BraiinsOS kernel. The PROVEN DCENT_OS runtime model (.25/.109/.129 from
# NAND) is: the squashfs IS the root partition, mounted read-only by the
# kernel. This builder now writes the squashfs RAW as partition 2 and boots
# root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait with no ramdisk
# (`bootm kernel - fdt`). See
#
#
# Usage: runs in WSL (sudo) OR Docker-as-root (debian:bookworm-slim, no loop
#   devices). Environment-agnostic: paths auto-derive from the script location,
#   sudo is a no-op when already root, and all FAT work uses mtools (no loop
#   devices / no mount) — the same portability fix applied to build_sd_image.sh.
#
set -euo pipefail

VARIANT="s19pro"
VERIFY_DONOR_ONLY=0
ROOTFS_INPUT=""
RUNTIME_INPUT=""
OUTPUT_INPUT=""

usage() {
    echo "Usage: $(basename "$0") [--variant s19pro|s17p|s17plus|t17|t17plus]" >&2
    echo "       Builds idle-first AM2 Zynq hardware beta SD boot media." >&2
    echo "       --rootfs FILE --runtime FILE --output FILE select explicit build inputs/output." >&2
    echo "       --verify-donor-only checks the held boot image and exits." >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --variant)
            VARIANT="${2:-}"
            shift 2
            ;;
        --variant=*)
            VARIANT="${1#--variant=}"
            shift
            ;;
        --rootfs|--runtime|--output)
            [ $# -ge 2 ] && [ -n "$2" ] || { usage; exit 2; }
            case "$1" in
                --rootfs) ROOTFS_INPUT="$2" ;;
                --runtime) RUNTIME_INPUT="$2" ;;
                --output) OUTPUT_INPUT="$2" ;;
            esac
            shift 2
            ;;
        --verify-donor-only)
            VERIFY_DONOR_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

case "$VARIANT" in
    s19pro)
        BOARD_TARGET="am2-s19pro"
        ARTIFACT_TARGET="am2-s19pro-sd"
        MODEL_LABEL="S19 Pro"
        CONFIG_NAME="dcentrald_s19pro_am2_baked_default.toml"
        IMAGE_NAME="dcentos-s19pro-sd.img"
        ;;
    s17p|s17pro|s17)
        VARIANT="s17p"
        BOARD_TARGET="am2-s17p"
        ARTIFACT_TARGET="am2-s17p-sd"
        MODEL_LABEL="S17 Pro"
        CONFIG_NAME="dcentrald_s17pro_am2_baked_default.toml"
        IMAGE_NAME="dcentos-s17pro-sd.img"
        ;;
    # 2026-08-27 Antminer 17-Series Complete Unlock Armada (agent B2): the
    # remaining BM1397 17-family SKUs get SD-first TRIAL media on the SAME
    # held Braiins am2-s17 boot components (A2 section 3: one image serves
    # S17/S17 Pro/S17+/T17/T17+). Zero NAND writes: the stock NAND u-boot
    # chain-loads the SD payload via uenvcmd (see the uEnv.txt notes), and a
    # `boot_stock` flag file on the FAT escapes back to the stock NAND chain.
    # Config: the am2-s17pro baked default (mining disabled, am2 safety
    # envelope) patched with the per-model geometry below.
    s17plus|s17+)
        VARIANT="s17plus"
        BOARD_TARGET="am2-s17plus"
        ARTIFACT_TARGET="am2-s17plus-sd"
        MODEL_LABEL="S17+"
        CONFIG_NAME="dcentrald_s17pro_am2_baked_default.toml"
        CONFIG_CHIP_COUNT=65
        CONFIG_MODEL="s17+"
        IMAGE_NAME="dcentos-s17plus-sd.img"
        ;;
    t17)
        VARIANT="t17"
        BOARD_TARGET="am2-t17"
        ARTIFACT_TARGET="am2-t17-sd"
        MODEL_LABEL="T17"
        CONFIG_NAME="dcentrald_s17pro_am2_baked_default.toml"
        CONFIG_CHIP_COUNT=30
        CONFIG_MODEL="t17"
        IMAGE_NAME="dcentos-t17-sd.img"
        ;;
    t17plus|t17+)
        VARIANT="t17plus"
        BOARD_TARGET="am2-t17plus"
        ARTIFACT_TARGET="am2-t17plus-sd"
        MODEL_LABEL="T17+"
        CONFIG_NAME="dcentrald_s17pro_am2_baked_default.toml"
        CONFIG_CHIP_COUNT=44
        CONFIG_MODEL="t17+"
        IMAGE_NAME="dcentos-t17plus-sd.img"
        ;;
    *)
        echo "ERROR: unsupported AM2 SD variant: $VARIANT (supported: s19pro, s17p, s17plus, t17, t17plus)" >&2
        exit 2
        ;;
esac

# Auto-derive the repo root from this script's location (scripts/ -> dcentos -> projects -> ROOT),
# so it works under WSL (/mnt/c/...) AND Docker (/work) without a hardcoded path.
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# sudo only when NOT already root (Docker-as-root has no sudo and needs none).
SUDO="sudo"; [ "$(id -u)" = "0" ] && SUDO=""
BRAIINS_IMG="${BRAIINS_IMG:-$PROJ/knowledge-base/firmware-archive/braiins-os_am2-s17_sd.img}"
BRAIINS_IMG_SIZE=112197632
BRAIINS_IMG_SHA256=b0444ad2a5e9b9e2b021ec756a40cb1448128545a42c77bdabb4363617d03579
DCENTOS_ROOTFS="${ROOTFS_INPUT:-$PROJ/DCENT_OS_Antminer/dcentos_rootfs.squashfs}"
NEW_BINARY="${RUNTIME_INPUT:-$PROJ/DCENT_OS_Antminer/dcentrald/target/armv7-unknown-linux-musleabihf/release/dcentrald}"
DCENTOS_CONFIG="$PROJ/DCENT_OS_Antminer/dcentrald/configs/$CONFIG_NAME"
OVERLAY="$PROJ/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay"
SD_IMAGE="${OUTPUT_INPUT:-$PROJ/DCENT_OS_Antminer/output/$IMAGE_NAME}"
# Resolve relative caller paths before changing into the private build directory.
DCENTOS_ROOTFS="$(realpath -ms -- "$DCENTOS_ROOTFS")"
NEW_BINARY="$(realpath -ms -- "$NEW_BINARY")"
SD_IMAGE="$(realpath -ms -- "$SD_IMAGE")"
export MTOOLS_SKIP_CHECK=1

# The donor is executable boot-chain input, not merely descriptive evidence.
# Validate its canonical identity before clearing any prior work directory or
# extracting a single byte. A modified or symlink-substituted donor must never
# produce media that looks evidence-backed.
validate_braiins_donor() {
    if [ ! -f "$BRAIINS_IMG" ] || [ -L "$BRAIINS_IMG" ]; then
        echo "ERROR: held Braiins AM2 donor must be a regular non-symlink file: $BRAIINS_IMG" >&2
        return 1
    fi

    local actual_size actual_sha256
    actual_size="$(stat -c '%s' -- "$BRAIINS_IMG")"
    if [ "$actual_size" != "$BRAIINS_IMG_SIZE" ]; then
        echo "ERROR: held Braiins AM2 donor size mismatch: expected $BRAIINS_IMG_SIZE, got $actual_size" >&2
        return 1
    fi

    command -v sha256sum >/dev/null 2>&1 || {
        echo "ERROR: sha256sum is required to verify the held Braiins AM2 donor" >&2
        return 1
    }
    actual_sha256="$(sha256sum -- "$BRAIINS_IMG")"
    actual_sha256="${actual_sha256%% *}"
    if [ "$actual_sha256" != "$BRAIINS_IMG_SHA256" ]; then
        echo "ERROR: held Braiins AM2 donor SHA256 mismatch" >&2
        echo "  expected: $BRAIINS_IMG_SHA256" >&2
        echo "  actual:   $actual_sha256" >&2
        return 1
    fi
    echo "  Held Braiins AM2 donor verified: $actual_size bytes, SHA256 $actual_sha256"
}

validate_braiins_donor
if [ "$VERIFY_DONOR_ONLY" = "1" ]; then
    exit 0
fi

if [ ! -f "$NEW_BINARY" ] || [ -L "$NEW_BINARY" ]; then
    echo "ERROR: current regular non-symlink armv7 dcentrald is required: $NEW_BINARY" >&2
    echo "       Cross-compile dcentrald before building AM2 SD media." >&2
    exit 1
fi

for build_input in "$DCENTOS_ROOTFS" "$DCENTOS_CONFIG"; do
    [ -f "$build_input" ] && [ ! -L "$build_input" ] || {
        echo "ERROR: build input must be a regular non-symlink file: $build_input" >&2
        exit 1
    }
done
INPUT_DIGESTS="$(sha256sum -- "$DCENTOS_ROOTFS" "$NEW_BINARY" "$DCENTOS_CONFIG")"

# Shared SD helpers (squashfs-root partition writer + magic check).
# shellcheck source=lib/sd_common.sh
. "$PROJ/DCENT_OS_Antminer/scripts/lib/sd_common.sh"

# The fixed output is later opened with truncating `dd`. Refuse direct,
# resolved-parent, symlink, and hard-link aliases to every executable/input
# artifact before clearing work state or opening an output.
sd_common::refuse_unsafe_output_alias "$SD_IMAGE" \
    "$BRAIINS_IMG" "$DCENTOS_ROOTFS" "$NEW_BINARY" "$DCENTOS_CONFIG"
sd_common::refuse_unsafe_output_alias "$SD_IMAGE.manifest.json" \
    "$SD_IMAGE" "$BRAIINS_IMG" "$DCENTOS_ROOTFS" "$NEW_BINARY" "$DCENTOS_CONFIG"

# Never accept a caller-selected recursive-cleanup target.  A private directory
# is allocated for this invocation only; the ownership sentinel keeps cleanup
# fail-closed if the path is unexpectedly replaced while the build is running.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/dcentos_sd_${VARIANT}.XXXXXX")" || {
    echo "ERROR: unable to allocate private AM2 SD build directory" >&2
    exit 1
}
WORKDIR_SENTINEL="$WORKDIR/.dcentos-private-am2-workdir"
: > "$WORKDIR_SENTINEL"
cleanup_private_workdir() {
    if [ -n "${WORKDIR:-}" ] && [ -f "${WORKDIR_SENTINEL:-}" ]; then
        $SUDO rm -rf -- "$WORKDIR"
    fi
}
trap cleanup_private_workdir EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$WORKDIR"/boot "$(dirname -- "$SD_IMAGE")"

# ============================================================
echo "=== Step 1: Extract FAT32 boot partition from BraiinsOS SD image (mtools, no loop) ==="
dd if="$BRAIINS_IMG" of="$WORKDIR/fat32.img" bs=512 skip=2048 count=81920 2>/dev/null
# mcopy all root files out of the FAT image — no mount / no loop device needed.
mcopy -i "$WORKDIR/fat32.img" -s -n "::*" "$WORKDIR/boot/"
for required in boot.bin u-boot.img system.bit.gz system_bm.bit.gz miner.btm miner.btm.sig fit.itb; do
    [ -f "$WORKDIR/boot/$required" ] || { echo "ERROR: Missing required boot artifact: $required"; exit 1; }
done
echo "  Boot files: $(ls "$WORKDIR/boot/")"

# ============================================================
echo ""
echo "=== Step 2: Extract kernel + DTB from FIT image ==="
python3 "$PROJ/DCENT_OS_Antminer/scripts/extract_fit.py" \
    "$WORKDIR/boot/fit.itb" "$WORKDIR"

ls -la "$WORKDIR/kernel.bin" "$WORKDIR/fdt.dtb"

# ============================================================
echo ""
echo "=== Step 3: Build DCENT_OS rootfs with new binary + fixes ==="

# Unsquash existing rootfs
$SUDO unsquashfs -d "$WORKDIR/rootfs_new" "$DCENTOS_ROOTFS"

# A structurally complete boot image with a stale daemon is not an installable
# DCENT_OS artifact.  Require the current cross-compiled runtime and bind its
# digest into the sidecar manifest; there is intentionally no warning-only
# fallback to the shared base rootfs binary.
$SUDO cp "$NEW_BINARY" "$WORKDIR/rootfs_new/usr/local/bin/dcentrald"
$SUDO chmod 755 "$WORKDIR/rootfs_new/usr/local/bin/dcentrald"
echo "  Installed current dcentrald binary ($(stat -c%s "$NEW_BINARY") bytes)"

# Install the selected idle-first, safety-clamped board config. Missing target
# identity is a hard failure; silently retaining a shared/rootfs default could
# select the wrong ASIC profile.
[ -f "$DCENTOS_CONFIG" ] || {
    echo "ERROR: selected $MODEL_LABEL config is missing: $DCENTOS_CONFIG" >&2
    exit 1
}
$SUDO cp "$DCENTOS_CONFIG" "$WORKDIR/rootfs_new/etc/dcentrald.toml"
if [ -n "${CONFIG_CHIP_COUNT:-}" ]; then
    # Patch ONLY the per-model geometry (3x65 / 3x30 / 3x44 chips, model
    # token) into the am2-s17pro baked default. Same mining-disabled,
    # am2-safety-envelope config otherwise.
    $SUDO awk -v chips="$CONFIG_CHIP_COUNT" -v model="$CONFIG_MODEL" '
        BEGIN { in_mining = 0 }
        /^\[/ { in_mining = ($0 ~ /^\[mining\]$/) ? 1 : 0; print; next }
        in_mining && /^[[:space:]]*serial_chip_count[[:space:]]*=/ { print "serial_chip_count = " chips; next }
        in_mining && /^[[:space:]]*model[[:space:]]*=/ { print "model = \"" model "\""; next }
        { print }
    ' "$WORKDIR/rootfs_new/etc/dcentrald.toml" > "$WORKDIR/rootfs_new/etc/dcentrald.toml.patched"
    $SUDO mv "$WORKDIR/rootfs_new/etc/dcentrald.toml.patched" "$WORKDIR/rootfs_new/etc/dcentrald.toml"
    echo "  Patched per-model geometry: serial_chip_count=$CONFIG_CHIP_COUNT model=$CONFIG_MODEL"
fi
echo "  Installed idle-first $MODEL_LABEL config"

# Fix dropbear — enable password auth
[ -f "$OVERLAY/etc/default/dropbear" ] && { $SUDO cp "$OVERLAY/etc/default/dropbear" "$WORKDIR/rootfs_new/etc/default/dropbear"; echo "  Fixed dropbear config (password auth enabled)"; }

# Copy updated init scripts (AM2 control-board family detection)
for s in S10modules S12fpga_identity S15pic_boot S82dcentrald; do
    [ -f "$OVERLAY/etc/init.d/$s" ] && $SUDO cp "$OVERLAY/etc/init.d/$s" "$WORKDIR/rootfs_new/etc/init.d/$s"
done
$SUDO mkdir -p "$WORKDIR/rootfs_new/usr/libexec/dcentos"
$SUDO cp "$OVERLAY/usr/libexec/dcentos/am2-fabric-identity.sh" "$WORKDIR/rootfs_new/usr/libexec/dcentos/"
$SUDO chmod 755 "$WORKDIR/rootfs_new/etc/init.d/S12fpga_identity"
echo "  Updated init scripts (AM2 control-board family detection)"

# CRITICAL (pass-2 fix P2-2): bake the am2 platform STAMPS into the rootfs. The
# shared dcentos_rootfs.squashfs base lacks them, so S82dcentrald (which keys
# IS_AM2 ONLY off these files) would land IS_AM2=0 on a real AM2 board ->
# the am2 UIO-mmap persistent fan custodian is never used, falling back to the
# unreliable devmem fan path. The kernel-cmdline dcent.platform= is NOT parsed
# into these, so the stamp MUST be baked here (not passed via bootargs).
$SUDO mkdir -p "$WORKDIR/rootfs_new/etc/dcentos"
echo "zynq-bm3-am2" | $SUDO tee "$WORKDIR/rootfs_new/etc/dcentos/platform" >/dev/null
echo "$BOARD_TARGET" | $SUDO tee "$WORKDIR/rootfs_new/etc/dcentos/board_target" >/dev/null
echo "  Baked AM2 platform stamps: platform=zynq-bm3-am2 board_target=$BOARD_TARGET (IS_AM2=1)"

# CRITICAL (pass-3 fix NEW-5): arch-guard the rootfs before re-squashing. The
# historical AArch64-init-in-ARMv7 PID-1 brick (PROJECT_LOG: shipped BB card
# looped every ~10s) is exactly this class — a stale cross-arch Buildroot output
# leaking an aarch64 /sbin/init into an armv7 card. Hard-fail on any non-ARMv7 PID1.
# shellcheck source=lib/buildroot_rootfs_arch_guard.sh
. "$PROJ/DCENT_OS_Antminer/scripts/lib/buildroot_rootfs_arch_guard.sh"
dcent_require_armv7_eabi_elf_paths "$WORKDIR/rootfs_new" "$MODEL_LABEL rootfs" \
    sbin/init bin/busybox usr/local/bin/dcentrald
echo "  Arch guard OK: /sbin/init + busybox + dcentrald are ARMv7 EABI ELF"

# Build new squashfs
$SUDO python3 "$PROJ/DCENT_OS_Antminer/scripts/provision_runtime_policy.py" "$WORKDIR/rootfs_new"
# The signature binds the final daemon bytes before the rootfs is compressed.
# Explicit signing inputs are passed through sudo rather than inferred from a
# mutable rootfs public-key file; no unsigned beta fallback exists.
$SUDO python3 "$PROJ/DCENT_OS_Antminer/scripts/runtime_image_manifest.py" prepare \
    --rootfs "$WORKDIR/rootfs_new" --board-target "$BOARD_TARGET" \
    --version "$(cat "$WORKDIR/rootfs_new/etc/dcentos-version")" \
    --channel "${DCENT_RELEASE_CHANNEL:-beta}" \
    --hardware-recipe "${DCENT_RELEASE_HARDWARE_RECIPE:-board-default}" \
    --key "${DCENT_RELEASE_SIGNING_KEY:?signed runtime image requires signing key}" \
    --pubkey "${DCENT_RELEASE_PUBKEY_FILE:?signed runtime image requires trusted public key}"
$SUDO rm -f "$WORKDIR/rootfs_dcentos.squashfs"
$SUDO mksquashfs "$WORKDIR/rootfs_new" "$WORKDIR/rootfs_dcentos.squashfs" \
    -comp xz -b 262144 -no-xattrs -noappend -processors 2 -no-progress
echo "  New rootfs: $(stat -c%s "$WORKDIR/rootfs_dcentos.squashfs") bytes"

# ============================================================
echo ""
echo "=== Step 4: Wrap kernel as uImage (no ramdisk — squashfs is the root partition) ==="

cd "$WORKDIR"

# Wrap kernel as uImage (legacy format that old U-Boot understands)
mkimage -A arm -O linux -T kernel -C none \
    -a 0x00008000 -e 0x00008000 \
    -n "DCENT_OS Linux 4.4.92" \
    -d kernel.bin uImage
echo "  uImage: $(stat -c%s uImage) bytes"

# NOTE: no uInitrd / FIT ramdisk wrap anymore. The squashfs is written RAW
# as partition 2 and the kernel mounts it directly as the read-only root
# (the proven .25/.109 NAND runtime model).

# ============================================================
echo ""
echo "=== Step 5: Build SD card image (p1 FAT32 boot + p2 RAW squashfs root) ==="

# Layout: p1 = FAT32 boot files @ 1 MiB; p2 = RAW DCENT_OS root squashfs.
# The squashfs IS the root partition (proven .25/.109 NAND runtime model):
# the kernel mounts /dev/mmcblk0p2 read-only as squashfs. No ramdisk.
BOOT_SIZE_MB=96
P1_OFFSET_MB=1
P2_OFFSET_MB=$((P1_OFFSET_MB + BOOT_SIZE_MB))
SQUASHFS_BYTES=$(stat -c%s "$WORKDIR/rootfs_dcentos.squashfs")
P2_SIZE_MB=$(( (SQUASHFS_BYTES + 1048575) / 1048576 + 2 ))
TOTAL_SIZE_MB=$((P2_OFFSET_MB + P2_SIZE_MB + 1))

# Create empty image
dd if=/dev/zero of="$SD_IMAGE" bs=1M count=$TOTAL_SIZE_MB 2>/dev/null

# Create partition table: p1 FAT32 LBA (0x0c) bootable + p2 Linux (0x83).
sfdisk "$SD_IMAGE" >/dev/null << EOF
label: dos
unit: sectors

start=$((P1_OFFSET_MB * 2048)), size=$((BOOT_SIZE_MB * 2048)), type=c, bootable
start=$((P2_OFFSET_MB * 2048)), size=$((P2_SIZE_MB * 2048)), type=83
EOF

# Format + fill the FAT32 boot partition with mtools (NO loop device / NO mount --
# the portable method that works in Docker-as-root and WSL alike). Build it in a
# standalone temp image, then dd it into p1 of the SD image.
BOOTPART="$WORKDIR/bootpart.fat"
dd if=/dev/zero of="$BOOTPART" bs=1M count=$BOOT_SIZE_MB 2>/dev/null
mkfs.vfat -F 32 -n DCENTOS "$BOOTPART" >/dev/null 2>&1

cp "$WORKDIR/fdt.dtb" "$WORKDIR/devicetree.dtb"

# Write DCENT_OS uEnv.txt that boots our kernel + p2 squashfs root from SD
# The BraiinsOS U-Boot loads u-boot.img which then reads uEnv.txt
cat > "$WORKDIR/uEnv.txt" << 'UENV'
# DCENT_OS lab SD boot for AM2 Zynq S17 Pro / S19 Pro control boards
# FIX (2026-06-10, SD boot defect session): squashfs IS the root partition
# (root=/dev/mmcblk0p2 rootfstype=squashfs ro), matching the proven
# .25/.109 NAND runtime model. No ramdisk (`bootm kernel - fdt`).
#
# Boot model (pass-2 correction M-2): the SD's OWN BraiinsOS BOOT.BIN (SPL) loads the
# BraiinsOS 2016.03 u-boot.img directly, whose `sdboot` runs `sd_uenvcmd` — there is NO
# stock-NAND chain-load and NO `uenvcmd` execution. All boot logic lives in sd_uenvcmd.

# CRITICAL (adversarial-pass fix 2026-06-10): a TOP-LEVEL bootargs= MUST be set
# (parity with build_am2_s19jpro_sd_disk_image.sh:512). BraiinsOS `sdboot` does
# `test -n ${bootargs} || setenv bootargs ...root=/dev/ram0...`; WITHOUT this line,
# if any clause inside sd_uenvcmd fails the kernel boots the BOS root=/dev/ram0
# default and panics. With it, the squashfs-root bootargs survive regardless.
bootargs=mem=228M console=ttyPS0,115200 root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait earlyprintk

# Memory addresses
bm_kernel_addr=0x2000000
bm_devicetree_addr=0x3000000

# STOCK-UNIT ENTRY (2026-08-27 armada, A2 section 3 boot model 2): on a STOCK
# unit (stock NAND u-boot intact, eFuse state irrelevant) the stock ROM u-boot
# scans the SD in its recovery path and EXECUTES a top-level `uenvcmd` — the
# documented Braiins stock-chain-load: `load mmc 0 0x3FFFFC0 u-boot.img; go
# 0x4000000` (BOS u-boot.img loaded 64-byte-header-aligned, jump to the
# binary). That is what makes SD trial boot a ZERO-NAND-WRITE path on an
# otherwise untouched stock unit. On the BOS-SPL path (this card's own
# BOOT.BIN) the resident BraiinsOS 2016.03 u-boot runs `sd_uenvcmd` and NEVER
# imports `uenvcmd`, so the line below is inert there — the pass-2 M-2
# boot-loop concern applied to re-entering an ALREADY-RUNNING BOS u-boot,
# which the sdboot path cannot do. After `go 0x4000000` the freshly entered
# BOS u-boot runs its own sdboot -> sd_uenvcmd below: both entries converge on
# the DCENT kernel.
uenvcmd=load mmc 0 0x3FFFFC0 u-boot.img && go 0x4000000

# ESCAPE HATCH (`boot_stock` flag file): create an empty file named
# `boot_stock` in this FAT partition to flip the BOS u-boot to the STOCK NAND
# boot chain (system_bm.bit stock-compat bitstream + stock mtd0 offsets) —
# the Braiins dual-boot contract (A2 section 3 boot model 3). Removing the
# file restores DCENT SD boot. Documented escape for ending an SD trial with
# zero NAND mutation: power off, add boot_stock (or pull the card), power on.

# FPGA bitstream load (explicit addresses, unzip before fpga loadb)
bm_bitstream_load_addr=0x1000000
bm_bitstream_addr=0x1800000
bm_load_bitstream=load mmc 0 ${bm_bitstream_load_addr} system.bit.gz && unzip ${bm_bitstream_load_addr} ${bm_bitstream_addr} && fpga loadb 0 ${bm_bitstream_addr} ${filesize}

# Boot args: RAW squashfs root on p2, mounted read-only by the kernel
bm_set_bootargs=setenv bootargs mem=228M console=ttyPS0,115200 root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait earlyprintk

# Stage 2: Load DCENT_OS from SD (overrides BraiinsOS default NAND boot)
bm_load_sd_images=fatload mmc 0 ${bm_kernel_addr} uImage && fatload mmc 0 ${bm_devicetree_addr} devicetree.dtb
sd_uenvcmd=echo === DCENT_OS Booting from SD ===; if run bm_load_bitstream; then echo FPGA programmed; else echo FPGA load failed - booting anyway; fi; run bm_load_sd_images && run bm_set_bootargs && bootm ${bm_kernel_addr} - ${bm_devicetree_addr}
UENV

python3 "$PROJ/DCENT_OS_Antminer/scripts/prepare_am2_fabric_boot.py" \
    --bitstream-gzip "$WORKDIR/boot/system.bit.gz" \
    --output-dir "$WORKDIR" --uenv "$WORKDIR/uEnv.txt"
mcopy -i "$BOOTPART" -o "$WORKDIR/am2-fabric.itb" "::am2-fabric.itb"

# Copy the boot chain + DCENT_OS kernel/DTB/uEnv into the FAT (mcopy, no mount).
for f in boot.bin u-boot.img system.bit.gz system_bm.bit.gz miner.btm miner.btm.sig; do
    mcopy -i "$BOOTPART" -o "$WORKDIR/boot/$f" "::$f"
done
mcopy -i "$BOOTPART" -o "$WORKDIR/uImage" "::uImage"
mcopy -i "$BOOTPART" -o "$WORKDIR/devicetree.dtb" "::devicetree.dtb"
mcopy -i "$BOOTPART" -o "$WORKDIR/uEnv.txt" "::uEnv.txt"
echo "  SD boot partition contents:"
mdir -i "$BOOTPART" :: 2>/dev/null | tail -n +4

# dd the formatted+filled FAT into p1 of the SD image (p1 starts at P1_OFFSET_MB).
dd if="$BOOTPART" of="$SD_IMAGE" bs=1M seek=$P1_OFFSET_MB conv=notrunc 2>/dev/null

# Write the DCENT_OS root squashfs RAW into partition 2 (magic-verified,
# bounds-checked). NEVER stage it as a file inside a filesystem — that was
# the "No init found" boot-loop defect.
sd_common::write_squashfs_root_partition "$SD_IMAGE" "$WORKDIR/rootfs_dcentos.squashfs" "$P2_OFFSET_MB" "$P2_SIZE_MB"

[ "$INPUT_DIGESTS" = "$(sha256sum -- "$DCENTOS_ROOTFS" "$NEW_BINARY" "$DCENTOS_CONFIG")" ] || {
    echo "ERROR: runtime/rootfs/config inputs changed during image construction" >&2
    exit 1
}

# Bind the exact image and held AM2/S17 donor evidence to an explicit support
# scope. Native execution is available for the exact beta target; physical
# qualification remains pending. This image authorizes external-media boot.
python3 "$PROJ/DCENT_OS_Antminer/scripts/write_sd_boot_media_manifest.py" \
    --image "$SD_IMAGE" \
    --target "$ARTIFACT_TARGET" \
    --board-target "$BOARD_TARGET" \
    --control-board-family zynq-bm3-am2 \
    --native-runtime-support experimental \
    --donor "$BRAIINS_IMG" \
    --runtime "$NEW_BINARY" \
    --complete-zynq-boot-set

echo ""
echo "============================================"
echo "  DCENT_OS SD Card Image: HARDWARE BETA"
echo "============================================"
echo "  Image: $SD_IMAGE"
echo "  Manifest: $SD_IMAGE.manifest.json"
echo "  Size:  $(stat -c%s "$SD_IMAGE") bytes ($(stat -c%s "$SD_IMAGE" | awk '{print int($1/1024/1024)}') MB)"
echo ""
echo "  Write to SD card:"
echo "    balenaEtcher: select $IMAGE_NAME"
echo "    Or: dd if=$IMAGE_NAME of=/dev/sdX bs=4M"
echo ""
echo "  Boot: Insert SD + power on $MODEL_LABEL (JP4 jumper to SD position)"
echo "  Configure a pool and Start mining to run the exact-target native beta."
echo "  This SD image grants no NAND install or firmware-write capability."
echo "  Setup: open http://<IP>/; use the provisioned key for SSH access."
echo "============================================"
