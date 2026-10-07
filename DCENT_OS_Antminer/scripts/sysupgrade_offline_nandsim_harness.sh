#!/usr/bin/env bash
#
# Offline sysupgrade write-path proof harness.
#
# Runs the REAL on-miner sysupgrade script against Linux MTD/UBI emulation.
# This is intentionally not a mock harness: if nandsim/UBI/libubootenv cannot
# be used, it exits 77 with SKIP_NANDSIM_UNAVAILABLE instead of reporting proof.
#
# Intended execution environment:
#   privileged disposable Linux container or VM with:
#     nandsim, ubi/ubifs kernel modules, mtd-utils, u-boot-tools
#
# Example:
#   DCENT_SYSUPGRADE_OFFLINE_CONTAINER=1 \
#     scripts/sysupgrade_offline_nandsim_harness.sh \
#       --target am2-s19jpro \
#       --package output/.../dcentos-sysupgrade-am2-s19jpro.tar \
#       --workdir /tmp/dcent-nandsim-proof

set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(CDPATH='' cd "$SCRIPT_DIR/.." && pwd)
PERSIST_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-persistent-state.sh"
TRANSACTION_LOCK_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-transaction-lock.sh"
TRANSACTION_WORKSPACE_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-transaction-workspace.sh"
PACKAGE_INPUT_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-package-input.sh"
ARCHIVE_ADMISSION_HELPER="$PROJECT_DIR/scripts/lib/sysupgrade_archive_admission.sh"
SESSION_LATCH_HELPER="$PROJECT_DIR/br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
UBI_IDENTITY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-ubi-identity.sh"
ZYNQ_GEOMETRY_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-zynq-geometry.sh"
UBOOT_ENV_ADMISSION_HELPER="$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-uboot-env-admission.sh"
NANDSIM_GEOMETRY_HELPER="$PROJECT_DIR/scripts/lib/zynq_nandsim_geometry.sh"
# 2026-09-15 (C1 adjudication, brief 1): the am2 writers hard-require the
# native AM2 OTA participant (05124af24) even in -T mode. The deployed
# participant (am2-native-ota.sh + am2_ota_boot.py + am2-nand-window) cannot
# run offline — no signed FPGA package, no dual10 window writer — so the
# offline stub keeps the env-snapshot/commit/apply custody real while
# no-oping the fabric rung. The writers refuse these overrides on the
# deployed /usr/sbin/sysupgrade path, so this stays an offline-proof-only
# channel.
AM2_OTA_OFFLINE_STUB="$PROJECT_DIR/scripts/lib/sysupgrade_am2_ota_offline_stub.sh"

[ -r "$NANDSIM_GEOMETRY_HELPER" ] || {
    echo "ERROR: missing nandsim geometry helper: $NANDSIM_GEOMETRY_HELPER" >&2
    exit 1
}
. "$NANDSIM_GEOMETRY_HELPER"

TARGET=""
PACKAGE=""
WORKDIR=""
RELEASE_KEY=""
PROBE_ONLY=0
GEOMETRY_ONLY=0
ALLOW_LAB_PACKAGE=0
REQUIRE_NANDSIM=${DCENT_REQUIRE_NANDSIM:-0}
NANDSIM_ID_BYTES=${DCENT_NANDSIM_ID_BYTES:-0x20,0xaa,0x00,0x15}
NANDSIM_OVERRIDESIZE=${DCENT_NANDSIM_OVERRIDESIZE:-11}
NANDSIM_PARTS=
NANDSIM_INACTIVE_MTD=${DCENT_NANDSIM_INACTIVE_MTD:-7}
NANDSIM_ERASESIZE_HEX=00020000
# CE-026 reverse A/B: the default is forward (current-fw=2, active mtd8 ->
# inactive mtd7).  Both layouts include both slots so the active rootfs_data can
# be mounted as ubi0 while the inactive slot is exercised as ubi1. --current-fw
# 1 selects active mtd7 -> inactive mtd8.
CURRENT_FW=${DCENT_NANDSIM_CURRENT_FW:-2}
NANDSIM_PARTS_REVERSE=
NANDSIM_LOADED_BY_HARNESS=0
ACTIVE_DATA_MOUNTED=0
ACTIVE_DATA_MOUNTPOINT_CREATED=0
INACTIVE_SEED_MOUNTED=0
INACTIVE_VERIFY_MOUNTED=0
INACTIVE_SEED_MOUNT=""
INACTIVE_VERIFY_MOUNT=""
CALLER_PERSIST_MOUNT=""
OFFLINE_FW_ENV_CONFIG=""
OFFLINE_UBOOT_ENV_PROC_MTD=""
OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT=""

usage() {
    cat <<'EOF'
Usage: sysupgrade_offline_nandsim_harness.sh --target TARGET --package TAR --workdir DIR [options]

Targets:
  am1-s9
  am2-s17pro
  am2-s19jpro
  am2-s19pro

Options:
  --release-key PATH       Embedded release_ed25519.pub used by sysupgrade
  --current-fw {1,2}       A/B direction. 2 (default) = forward (active mtd8 ->
                           inactive mtd7). 1 = reverse (active mtd7 -> inactive
                           mtd8); both slots exist in the nandsim layout.
  --allow-lab-package      Permit unsigned/non-release lab packages for harness development
  --probe-only             Only check kernel/tool availability
  --geometry-only          Attach one exact AM2 slot and prove its complete
                           authoritative UBI tuple without parsing a package
  --require-nandsim        Missing nandsim/UBI support exits 1 instead of 77
  -h, --help               Show this help

Success prints OFFLINE_NANDSIM_PROOF_OK only after the real sysupgrade writer
has refused to flip on injected session-admission and persistence failures,
copied the complete operator-resolved persistent-state fixture, survived a
read-only remount, updated inactive UBI payload volumes, and fw_printenv
verifies the boot-selector flip.  This is a write-path proof: it does not boot
the new slot or claim S82/S99 first-boot commit/rollback coverage.
The reverse direction prints a DISTINCT sentinel (direction=reverse).
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target) TARGET=${2:-}; shift 2 ;;
        --current-fw) CURRENT_FW=${2:-}; shift 2 ;;
        --package) PACKAGE=${2:-}; shift 2 ;;
        --workdir) WORKDIR=${2:-}; shift 2 ;;
        --release-key) RELEASE_KEY=${2:-}; shift 2 ;;
        --allow-lab-package) ALLOW_LAB_PACKAGE=1; shift ;;
        --probe-only) PROBE_ONLY=1; shift ;;
        --geometry-only) GEOMETRY_ONLY=1; shift ;;
        --require-nandsim) REQUIRE_NANDSIM=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

skip_unavailable() {
    echo "SKIP_NANDSIM_UNAVAILABLE: $*" >&2
    if [ "$REQUIRE_NANDSIM" = "1" ]; then
        exit 1
    fi
    exit 77
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

path_is_mounted() {
    local path=$1
    awk -v path="$path" '$5 == path { found=1 } END { exit found ? 0 : 1 }' \
        /proc/self/mountinfo 2>/dev/null
}

cleanup() {
    local status=$?
    set +e
    if [ "$INACTIVE_VERIFY_MOUNTED" = "1" ] && [ -n "$INACTIVE_VERIFY_MOUNT" ]; then
        umount "$INACTIVE_VERIFY_MOUNT" >/dev/null 2>&1
    fi
    if [ "$INACTIVE_SEED_MOUNTED" = "1" ] && [ -n "$INACTIVE_SEED_MOUNT" ]; then
        umount "$INACTIVE_SEED_MOUNT" >/dev/null 2>&1
    fi
    if [ -n "$CALLER_PERSIST_MOUNT" ] && path_is_mounted "$CALLER_PERSIST_MOUNT"; then
        umount "$CALLER_PERSIST_MOUNT" >/dev/null 2>&1
    fi
    ubidetach -d 1 >/dev/null 2>&1
    if [ "$ACTIVE_DATA_MOUNTED" = "1" ]; then
        umount /data >/dev/null 2>&1
    fi
    ubidetach -d 0 >/dev/null 2>&1
    if [ "$ACTIVE_DATA_MOUNTPOINT_CREATED" = "1" ]; then
        rmdir /data >/dev/null 2>&1
    fi
    if [ "$NANDSIM_LOADED_BY_HARNESS" = "1" ]; then
        modprobe -r nandsim >/dev/null 2>&1 || true
    fi
    return "$status"
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || skip_unavailable "missing tool: $1"
}

need_root() {
    [ "$(id -u)" = "0" ] || skip_unavailable "must run as root in a privileged disposable Linux container/VM"
}

load_module() {
    local module=$1
    if grep -q "^${module} " /proc/modules 2>/dev/null; then
        return 0
    fi
    modprobe "$module" >/tmp/dcent-nandsim-modprobe.out 2>&1 || {
        cat /tmp/dcent-nandsim-modprobe.out >&2 || true
        skip_unavailable "cannot load kernel module: $module"
    }
}

load_ubi_module() {
    if grep -q '^ubi ' /proc/modules 2>/dev/null; then
        return 0
    fi
    modprobe ubi fm_autoconvert=0 >/tmp/dcent-nandsim-modprobe.out 2>&1 || {
        cat /tmp/dcent-nandsim-modprobe.out >&2 || true
        skip_unavailable "cannot load kernel module: ubi"
    }
}

verify_nandsim_geometry() {
    local erasesize
    erasesize=$(awk -v expected="$NANDSIM_ERASESIZE_HEX" '
        /NAND simulator|nandsim|NAND 256MiB/ {
            if ($3 == expected) {
                print $3;
                exit;
            }
        }
    ' /proc/mtd 2>/dev/null)
    [ "$erasesize" = "$NANDSIM_ERASESIZE_HEX" ] || {
        awk '/NAND simulator|nandsim|NAND/ {print}' /proc/mtd >&2 2>/dev/null || true
        skip_unavailable "nandsim must use 128KiB eraseblocks for Xilinx UBI layout proof"
    }
}

load_nandsim() {
    if grep -q "^nandsim " /proc/modules 2>/dev/null; then
        verify_nandsim_geometry
        return 0
    fi
    modprobe nandsim "id_bytes=$NANDSIM_ID_BYTES" "overridesize=$NANDSIM_OVERRIDESIZE" \
        "parts=$NANDSIM_PARTS" \
        >/tmp/dcent-nandsim-modprobe.out 2>&1 || {
        cat /tmp/dcent-nandsim-modprobe.out >&2 || true
        skip_unavailable "cannot load kernel module: nandsim"
    }
    NANDSIM_LOADED_BY_HARNESS=1
    verify_nandsim_geometry
}

sysupgrade_path_for_target() {
    case "$1" in
        am1-s9)
            printf '%s\n' "$PROJECT_DIR/br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade"
            ;;
        am2-s17pro)
            printf '%s\n' "$PROJECT_DIR/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade"
            ;;
        am2-s19jpro)
            printf '%s\n' "$PROJECT_DIR/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade"
            ;;
        am2-s19pro)
            printf '%s\n' "$PROJECT_DIR/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade"
            ;;
        *)
            die "unsupported target '$1' (expected am1-s9, am2-s17pro, am2-s19jpro, or am2-s19pro)"
            ;;
    esac
}

coarse_board_for_target() {
    case "$1" in
        am1-s9) printf 'am1-s9\n' ;;
        am2-s17pro) printf 'am2-s17p\n' ;;
        am2-s19jpro) printf 'am2-s19j\n' ;;
        am2-s19pro) printf 'am2-s19pro\n' ;;
        *) die "unsupported target '$1'" ;;
    esac
}

volume_lebs_for_target() {
    case "$1" in
        # rootfs_data is operator-managed on S9.  Twenty-four LEBs are the
        # smallest default-mkfs UBIFS fixture at this geometry; the historical
        # eight-LEB placeholder cannot contain a mountable UBIFS filesystem.
        am1-s9) printf '32 134 24\n' ;;
        am2-s17pro|am2-s19jpro|am2-s19pro) printf '23 179 210\n' ;;
        *) die "unsupported target '$1'" ;;
    esac
}

ceil_div() {
    local value=$1 divisor=$2
    printf '%s\n' "$(( (value + divisor - 1) / divisor ))"
}

max_int() {
    if [ "$1" -gt "$2" ]; then
        printf '%s\n' "$1"
    else
        printf '%s\n' "$2"
    fi
}

require_nandsim_partition() {
    local mtd=$1 expected_size=${2:-} label="NAND simulator partition $1"
    if [ -n "$expected_size" ]; then
        awk -v mtd="mtd${mtd}:" -v size="$expected_size" -v erase="$NANDSIM_ERASESIZE_HEX" -v label="$label" '
            $1 == mtd && $2 == size && $3 == erase && index($0, label) { found=1 }
            END { exit found ? 0 : 1 }
        ' /proc/mtd 2>/dev/null || {
            awk -v mtd="mtd${mtd}:" '$1 == mtd { print }' /proc/mtd >&2 2>/dev/null || true
            skip_unavailable "mtd$mtd is not the expected nandsim partition '$label'"
        }
    else
        awk -v mtd="mtd${mtd}:" -v erase="$NANDSIM_ERASESIZE_HEX" -v label="$label" '
            $1 == mtd && $3 == erase && index($0, label) { found=1 }
            END { exit found ? 0 : 1 }
        ' /proc/mtd 2>/dev/null || {
            awk -v mtd="mtd${mtd}:" '$1 == mtd { print }' /proc/mtd >&2 2>/dev/null || true
            skip_unavailable "mtd$mtd is not the expected nandsim partition '$label'"
        }
    fi
    [ -c "/dev/mtd$mtd" ] || skip_unavailable "missing real MTD character device /dev/mtd$mtd for nandsim"
}

find_nandsim_mtd() {
    require_nandsim_partition 4 00080000
    # Persistence proof needs the active slot attached as ubi0 and the inactive
    # slot attached as ubi1 in both A/B directions.
    if [ "$DCENT_ZYNQ_NANDSIM_SLOT_MTD_SIZE_HEX" = - ]; then
        require_nandsim_partition "$CMDLINE_UBI_MTD" ""
        require_nandsim_partition "$NANDSIM_INACTIVE_MTD" ""
    else
        require_nandsim_partition "$CMDLINE_UBI_MTD" \
            "$DCENT_ZYNQ_NANDSIM_SLOT_MTD_SIZE_HEX"
        require_nandsim_partition "$NANDSIM_INACTIVE_MTD" \
            "$DCENT_ZYNQ_NANDSIM_SLOT_MTD_SIZE_HEX"
    fi
    printf '%s\n' "$NANDSIM_INACTIVE_MTD"
}

verify_attached_ubi_geometry() {
    local ubi_num=$1 mtd=$2 peb leb total reserved bad available expected

    [ "$DCENT_ZYNQ_NANDSIM_GEOMETRY_AUTHORITY" = am2-live-exact ] || return 0
    peb=$(cat "/sys/class/mtd/mtd$mtd/erasesize" 2>/dev/null || true)
    leb=$(cat "/sys/class/ubi/ubi$ubi_num/eraseblock_size" 2>/dev/null || true)
    total=$(cat "/sys/class/ubi/ubi$ubi_num/total_eraseblocks" 2>/dev/null || true)
    reserved=$(cat "/sys/class/ubi/ubi$ubi_num/reserved_for_bad" 2>/dev/null || true)
    bad=$(cat "/sys/class/ubi/ubi$ubi_num/bad_peb_count" 2>/dev/null || true)
    available=$(cat "/sys/class/ubi/ubi$ubi_num/avail_eraseblocks" 2>/dev/null || true)
    if ! dcent_zynq_nandsim_attached_tuple_matches \
        "$peb" "$leb" "$total" "$reserved" "$bad" "$available"; then
        expected=$(dcent_zynq_nandsim_expected_tuple)
        skip_unavailable "ubi$ubi_num on mtd$mtd is not AM2 geometry authority: expected $expected; observed peb=$peb leb=$leb total=$total reserved_for_bad=$reserved bad=$bad available=$available (the loaded UBI implementation must have CONFIG_MTD_UBI_FASTMAP=n)"
    fi
}

format_nandsim_mtd() {
    local mtd=$1
    if [ "$DCENT_ZYNQ_NANDSIM_VID_OFFSET" = - ]; then
        ubiformat "/dev/mtd$mtd" -y >/dev/null
    else
        ubiformat "/dev/mtd$mtd" -y -O "$DCENT_ZYNQ_NANDSIM_VID_OFFSET" >/dev/null
    fi
}

attach_nandsim_mtd() {
    local mtd=$1 ubi_num=$2
    if [ "$DCENT_ZYNQ_NANDSIM_VID_OFFSET" = - ]; then
        ubiattach /dev/ubi_ctrl -m "$mtd" -d "$ubi_num" >/dev/null
    else
        ubiattach /dev/ubi_ctrl -m "$mtd" -d "$ubi_num" \
            -O "$DCENT_ZYNQ_NANDSIM_VID_OFFSET" \
            -b "$DCENT_ZYNQ_NANDSIM_BEB_LIMIT" >/dev/null
    fi
    verify_attached_ubi_geometry "$ubi_num" "$mtd"
}

create_nandsim_mtd() {
    local mtd
    load_nandsim
    mtd=$(find_nandsim_mtd)
    [ -n "$mtd" ] || skip_unavailable "nandsim loaded but no simulator MTD appeared in /proc/mtd"
    [ -e "/dev/mtd$mtd" ] || skip_unavailable "missing /dev/mtd$mtd for nandsim"
    printf '%s\n' "$mtd"
}

create_ubi_device_nodes() {
    local ubi_path name dev major minor
    for ubi_path in /sys/class/ubi/ubi[01]*; do
        [ -d "$ubi_path" ] || continue
        name=$(basename "$ubi_path")
        dev=$(cat "$ubi_path/dev" 2>/dev/null || true)
        [ -n "$dev" ] || continue
        major=${dev%%:*}
        minor=${dev##*:}
        [ -e "/dev/$name" ] || mknod -m 600 "/dev/$name" c "$major" "$minor" 2>/dev/null || true
    done
}

format_empty_rootfs_data() {
    local ubi_num=$1 volume_dev=$2 data_lebs=$3
    local leb_size min_io_size
    local empty_data_root="$WORKDIR/empty-rootfs-data-ubi$ubi_num"
    local empty_data_image="$WORKDIR/empty-rootfs-data-ubi$ubi_num.ubifs"

    leb_size=$(cat "/sys/class/ubi/ubi$ubi_num/eraseblock_size" 2>/dev/null || true)
    min_io_size=$(cat "/sys/class/ubi/ubi$ubi_num/min_io_size" 2>/dev/null || true)
    case "$leb_size" in
        *[!0-9]*|"") skip_unavailable "cannot read UBI LEB size for rootfs_data fixture" ;;
    esac
    case "$min_io_size" in
        *[!0-9]*|"") skip_unavailable "cannot read UBI minimum I/O size for rootfs_data fixture" ;;
    esac

    rm -rf "$empty_data_root" "$empty_data_image"
    mkdir "$empty_data_root"
    mkfs.ubifs -q -r "$empty_data_root" -m "$min_io_size" -e "$leb_size" \
        -c "$data_lebs" -o "$empty_data_image"
    ubiupdatevol "$volume_dev" "$empty_data_image" >/dev/null
}

prepare_inactive_ubi() {
    local mtd=$1 target=$2 kernel_lebs=$3 rootfs_lebs=$4 data_lebs=$5 kernel_src=$6 rootfs_src=$7
    local leb_size required_kernel_lebs required_rootfs_lebs

    ubidetach -m "$mtd" >/dev/null 2>&1 || true
    ubidetach -d 1 >/dev/null 2>&1 || true
    format_nandsim_mtd "$mtd"
    attach_nandsim_mtd "$mtd" 1

    leb_size=$(cat /sys/class/ubi/ubi1/eraseblock_size 2>/dev/null || true)
    case "$leb_size" in
        *[!0-9]*|"") skip_unavailable "cannot read UBI LEB size for offline fixture" ;;
    esac

    if [ "$target" = "am1-s9" ]; then
        required_kernel_lebs=$(ceil_div "$(wc -c < "$kernel_src" | tr -d '[:space:]')" "$leb_size")
        required_rootfs_lebs=$(ceil_div "$(wc -c < "$rootfs_src" | tr -d '[:space:]')" "$leb_size")
        kernel_lebs=$(max_int "$kernel_lebs" "$required_kernel_lebs")
        rootfs_lebs=$(max_int "$rootfs_lebs" "$required_rootfs_lebs")
    fi

    ubimkvol /dev/ubi1 -N kernel -s "$((kernel_lebs * leb_size))" -t dynamic >/dev/null
    ubimkvol /dev/ubi1 -N rootfs -s "$((rootfs_lebs * leb_size))" -t dynamic >/dev/null
    if [ "$data_lebs" -gt 0 ]; then
        ubimkvol /dev/ubi1 -N rootfs_data -s "$((data_lebs * leb_size))" -t dynamic >/dev/null
    fi
    create_ubi_device_nodes
    if [ "$data_lebs" -gt 0 ]; then
        format_empty_rootfs_data 1 /dev/ubi1_2 "$data_lebs"
    fi
    ubidetach -d 1 >/dev/null
}

seed_active_data_fixture() {
    local root=$1

    umask 077
    mkdir -p "$root/keys/dropbear" "$root/config" "$root/profiles" \
        "$root/dcent" "$root/overlay/etc/upper" "$root/overlay/etc/work"
    printf '%s\n' 'ssh-ed25519 ACTIVE-DATA-KEY dcent-offline-test' \
        >"$root/keys/dropbear/authorized_keys"
    printf '%s\n' 'ACTIVE-HOST-KEY-BYTES' \
        >"$root/keys/dropbear/dropbear_ed25519_host_key"
    printf '%s\n' 'include-hidden-key-state' >"$root/keys/.key-policy"
    dd if=/dev/zero of="$root/keys/random-seed" bs=512 count=1 2>/dev/null
    printf '%s\n' '{"fleet":"offline-proof"}' >"$root/config/.fleet.json"
    printf '%s\n' 'voltage_mv = 8600' >"$root/profiles/.factory-calibration"
    printf '%s\n' '{"credential":"ACTIVE-CREDENTIAL"}' >"$root/dcent/auth.json"
    printf '%s\n' 'ssh-ed25519 ACTIVE-DASHBOARD-KEY dcent-dashboard' \
        >"$root/dcent/authorized_keys"
    printf '%s\n' 'include-hidden-dashboard-state' >"$root/dcent/.identity"
    printf '%s\n' '[mining]' 'enabled = true' >"$root/dcentrald.toml"
    printf '%s\n' 'active-hot-deploy-binary-must-not-migrate' >"$root/dcentrald"
    printf '%s\n' 'DCENT_RUNTIME_DERIVED=1' >"$root/dcentrald-env"
    printf '%s\n' '#!/bin/sh' 'active-derived-launcher-must-not-migrate' \
        >"$root/dcentrald_standalone_boot.sh"
    printf '%s\n' 'active-management-backup-must-not-migrate' \
        >"$root/dcentrald.toml.mgmt-bak"
    printf '%s\n' 'slot-local-overlay-must-not-migrate' \
        >"$root/overlay/etc/upper/.slot-local"

    chmod 0700 "$root/keys" "$root/keys/dropbear" "$root/config" \
        "$root/profiles" "$root/dcent"
    chmod 0600 "$root/keys/dropbear/authorized_keys" \
        "$root/keys/dropbear/dropbear_ed25519_host_key" \
        "$root/keys/random-seed" \
        "$root/dcent/auth.json" "$root/dcent/authorized_keys" \
        "$root/dcentrald.toml"
}

prepare_active_data_mount() {
    local mtd=$1 kernel_lebs=$2 rootfs_lebs=$3 data_lebs=$4 leb_size

    if path_is_mounted /data; then
        die "refusing to cover an existing /data mount; use a clean disposable container"
    fi
    if [ -e /data ] || [ -L /data ]; then
        [ -d /data ] && [ ! -L /data ] || \
            die "refusing non-directory or symlink /data in disposable container"
        # virtme shares the host root tree, so the covered directory may have
        # host-visible entries.  The harness never edits those underlying
        # bytes: ubi0:rootfs_data covers them until the EXIT cleanup unmount.
    else
        mkdir /data
        ACTIVE_DATA_MOUNTPOINT_CREATED=1
    fi

    ubidetach -m "$mtd" >/dev/null 2>&1 || true
    ubidetach -d 0 >/dev/null 2>&1 || true
    format_nandsim_mtd "$mtd"
    attach_nandsim_mtd "$mtd" 0
    leb_size=$(cat /sys/class/ubi/ubi0/eraseblock_size 2>/dev/null || true)
    case "$leb_size" in
        *[!0-9]*|"") skip_unavailable "cannot read active UBI LEB size for offline fixture" ;;
    esac
    ubimkvol /dev/ubi0 -N kernel -s "$((kernel_lebs * leb_size))" -t dynamic >/dev/null
    ubimkvol /dev/ubi0 -N rootfs -s "$((rootfs_lebs * leb_size))" -t dynamic >/dev/null
    ubimkvol /dev/ubi0 -N rootfs_data -s "$((data_lebs * leb_size))" -t dynamic >/dev/null
    create_ubi_device_nodes
    format_empty_rootfs_data 0 /dev/ubi0_2 "$data_lebs"
    mount -t ubifs -o rw ubi0:rootfs_data /data
    ACTIVE_DATA_MOUNTED=1
    path_is_mounted /data || die "active ubi0:rootfs_data fixture mount is not visible"
    seed_active_data_fixture /data
}

seed_stale_inactive_data_fixture() {
    local mtd=$1 mountpoint=$2

    attach_nandsim_mtd "$mtd" 1
    create_ubi_device_nodes
    mkdir -p "$mountpoint"
    mount -t ubifs -o rw ubi1:rootfs_data "$mountpoint"
    INACTIVE_SEED_MOUNTED=1

    umask 077
    mkdir -p "$mountpoint/keys/dropbear" "$mountpoint/dcent" \
        "$mountpoint/overlay/etc/upper" "$mountpoint/overlay/etc/work"
    printf '%s\n' 'STALE-INACTIVE-HOST-KEY' \
        >"$mountpoint/keys/dropbear/dropbear_ed25519_host_key"
    printf '%s\n' '{"credential":"STALE-INACTIVE-CREDENTIAL"}' \
        >"$mountpoint/dcent/auth.json"
    printf '%s\n' 'stale-inactive-unresolved-session' \
        >"$mountpoint/dcent/dcentrald-hardware-session.unresolved"
    printf '%s\n' 'stale-inactive-crash-latch' \
        >"$mountpoint/dcent/dcentrald-hardware-session.crash-latched"
    mkdir "$mountpoint/dcent/.dcentrald-session-latch.lock"
    printf '%s\n' 'stale-managed-entry-with-no-active-source' \
        >"$mountpoint/dcentos-compat"
    printf '%s\n' 'stale-hot-deploy-binary' >"$mountpoint/dcentrald"
    printf '%s\n' 'STALE-INACTIVE-ENV' >"$mountpoint/dcentrald-env"
    printf '%s\n' 'STALE-INACTIVE-LAUNCHER' \
        >"$mountpoint/dcentrald_standalone_boot.sh"
    printf '%s\n' 'STALE-INACTIVE-MANAGEMENT-BACKUP' \
        >"$mountpoint/dcentrald.toml.mgmt-bak"
    dd if=/dev/zero of="$mountpoint/keys/random-seed" \
        bs=512 count=1 2>/dev/null
    printf '%s\n' 'stale-slot-overlay' \
        >"$mountpoint/overlay/etc/upper/stale.conf"
    chmod 0700 "$mountpoint/dcent"
    chmod 0600 "$mountpoint/dcent/auth.json" \
        "$mountpoint/keys/dropbear/dropbear_ed25519_host_key" \
        "$mountpoint/keys/random-seed"
    sync

    umount "$mountpoint"
    INACTIVE_SEED_MOUNTED=0
    rmdir "$mountpoint"
    ubidetach -d 1 >/dev/null
}

extract_package_payloads() {
    local tarball=$1 outdir=$2 expected_prefix=$3
    mkdir -p "$outdir"
    tar xf "$tarball" -C "$outdir"
    local subdir="$outdir/sysupgrade-$expected_prefix"
    [ -f "$subdir/kernel" ] || die "package missing $subdir/kernel"
    [ -f "$subdir/root" ] || die "package missing $subdir/root"
    printf '%s\n' "$subdir"
}

package_manifest_version() {
    local manifest=$1
    sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | sed -n '1p'
}

seed_fw_env_fixture() {
    local work=$1
    local env_txt="$work/fw_env.txt"
    local env_a="$work/fw_env_a.bin"
    local env_img="$work/fw_env.bin"

    cat >"$env_txt" <<EOF
firmware=${SEED_FIRMWARE:-2}
upgrade_stage=1
first_boot=no
bootcmd=run boot_dcent
EOF
    mkenvimage -r -s 0x20000 -o "$env_a" "$env_txt" >/dev/null
    rm -f "$env_img"
    dd if=/dev/zero of="$env_img" bs=1 count=0 seek=$((0x40000)) >/dev/null 2>&1
    dd if="$env_a" of="$env_img" bs=1 seek=0 conv=notrunc >/dev/null 2>&1
    dd if="$env_a" of="$env_img" bs=1 seek=$((0x20000)) conv=notrunc >/dev/null 2>&1

    require_nandsim_partition 4 00080000
    flash_erase /dev/mtd4 0 0 >/dev/null
    nandwrite -p /dev/mtd4 "$env_img" >/dev/null

    [ -n "$OFFLINE_FW_ENV_CONFIG" ] || die "offline fw_env config path is unset"
    [ -n "$OFFLINE_UBOOT_ENV_PROC_MTD" ] || die "offline proc MTD evidence path is unset"
    [ -n "$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT" ] || die "offline sysfs MTD evidence root is unset"

    cat >"$OFFLINE_FW_ENV_CONFIG" <<EOF
/dev/mtd4 0x00000 0x20000 0x20000 1
/dev/mtd4 0x20000 0x20000 0x20000 1
EOF
    chown 0:0 "$OFFLINE_FW_ENV_CONFIG"
    chmod 0644 "$OFFLINE_FW_ENV_CONFIG"

    cat >"$OFFLINE_UBOOT_ENV_PROC_MTD" <<EOF
dev:    size   erasesize  name
mtd4: 00080000 00020000 "uboot_env"
EOF
    mkdir -p "$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT/mtd4"
    printf '%s\n' uboot_env >"$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT/mtd4/name"
    printf '%s\n' 524288 >"$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT/mtd4/size"
    printf '%s\n' 131072 >"$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT/mtd4/erasesize"
    cat /sys/class/mtd/mtd4/dev >"$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT/mtd4/dev"

    chown 0:0 /dev/mtd4
    chmod 0600 /dev/mtd4
    fw_printenv -c "$OFFLINE_FW_ENV_CONFIG" firmware >/dev/null 2>&1 || \
        skip_unavailable "fw_printenv cannot read the offline fw_env fixture"
}

assert_boot_environment() {
    local expected_firmware=$1 expected_stage=$2 expected_first_boot=$3 context=$4
    local snapshot firmware stage first_boot
    snapshot=$(fw_printenv -c "$OFFLINE_FW_ENV_CONFIG" \
        firmware upgrade_stage first_boot 2>/dev/null) || \
        die "$context: cannot read the complete boot environment"
    firmware=$(printf '%s\n' "$snapshot" | sed -n 's/^firmware=//p')
    stage=$(printf '%s\n' "$snapshot" | sed -n 's/^upgrade_stage=//p')
    first_boot=$(printf '%s\n' "$snapshot" | sed -n 's/^first_boot=//p')
    [ "$firmware" = "$expected_firmware" ] || \
        die "$context: firmware=$firmware, expected $expected_firmware"
    [ "$stage" = "$expected_stage" ] || \
        die "$context: upgrade_stage=$stage, expected $expected_stage"
    [ "$first_boot" = "$expected_first_boot" ] || \
        die "$context: first_boot=${first_boot:-missing}, expected $expected_first_boot"
}

run_first_boot_readback_negative_probes() {
    fw_setenv -c "$OFFLINE_FW_ENV_CONFIG" first_boot no
    if (assert_boot_environment "$EXPECTED_POSTFLIP_FIRMWARE" 0 yes \
        "wrong first_boot negative probe") >/dev/null 2>&1; then
        die "boot-environment assertion accepted wrong first_boot=no"
    fi

    fw_setenv -c "$OFFLINE_FW_ENV_CONFIG" first_boot
    if (assert_boot_environment "$EXPECTED_POSTFLIP_FIRMWARE" 0 yes \
        "missing first_boot negative probe") >/dev/null 2>&1; then
        die "boot-environment assertion accepted missing first_boot"
    fi

    fw_setenv -c "$OFFLINE_FW_ENV_CONFIG" first_boot yes
    assert_boot_environment "$EXPECTED_POSTFLIP_FIRMWARE" 0 yes \
        "first_boot negative-probe restoration failed"
    echo "OFFLINE_NANDSIM_FIRST_BOOT_READBACK_NEGATIVE_PROOF_OK target=$TARGET"
}

run_session_interlock_failure_probe() {
    local log=$1 status
    local unresolved=/data/dcent/dcentrald-hardware-session.unresolved

    [ ! -e "$unresolved" ] && [ ! -L "$unresolved" ] || \
        die "operator-resolved fixture unexpectedly contains an unresolved session"
    [ ! -e /data/dcent/dcentrald-hardware-session.crash-latched ] && \
        [ ! -L /data/dcent/dcentrald-hardware-session.crash-latched ] || \
        die "operator-resolved fixture unexpectedly contains a crash latch"
    [ ! -e /data/dcent/.dcentrald-session-latch.lock ] && \
        [ ! -L /data/dcent/.dcentrald-session-latch.lock ] || \
        die "operator-resolved fixture unexpectedly contains a session admission lock"

    umask 077
    printf '%s\n' 'offline-proof-active-unresolved-session' >"$unresolved"
    chmod 0600 "$unresolved"
    sync
    rm -f "$UBIUPDATEVOL_AUDIT_LOG"

    set +e
    env "${ENV_ARGS[@]}" "$SYSUPGRADE_SHELL" "$SYSUPGRADE" -f "$PACKAGE" \
        >"$log" 2>&1
    status=$?
    set -e
    [ "$status" -ne 0 ] || \
        die "sysupgrade accepted an active unresolved hardware session"
    grep -Fq 'Error: sysupgrade requires a manually resolved hardware session.' "$log" || {
        cat "$log" >&2
        die "session-interlock probe did not reach the active-state refusal"
    }
    grep -Fq 'dcentrald-session-latch: update blocked by active or unresolved hardware session /data/dcent/dcentrald-hardware-session.unresolved' "$log" || {
        cat "$log" >&2
        die "session-interlock refusal was not caused by the exact unresolved-session marker"
    }
    if [ -s "$UBIUPDATEVOL_AUDIT_LOG" ]; then
        cat "$UBIUPDATEVOL_AUDIT_LOG" >&2
        die "session-interlock refusal invoked ubiupdatevol"
    fi
    assert_boot_environment "$SEED_FIRMWARE" 1 no \
        "session-interlock refusal changed the pre-flip boot environment"
    [ ! -e "$SYSUPGRADE_LOCK_DIR" ] && [ ! -L "$SYSUPGRADE_LOCK_DIR" ] || \
        die "session-interlock refusal did not release its transaction lock"

    rm -f "$unresolved"
    sync
    echo "OFFLINE_NANDSIM_SESSION_INTERLOCK_PROOF_OK target=$TARGET ubiupdatevol_calls=0 firmware=$SEED_FIRMWARE upgrade_stage=1 first_boot=no"
}

run_persistence_preflip_failure_probe() {
    local log=$1 concurrent_log=$2 owner_pid owner_status lock_wait

    # The helper requires dashboard credentials to remain owner-only.  Make
    # the active credential unsafe, prove that this exact persistence gate is
    # reached, and prove that neither boot selector has changed.
    chmod 0644 /data/dcent/auth.json
    rm -f "$UBIUPDATEVOL_AUDIT_LOG"
    env "${ENV_ARGS[@]}" "$SYSUPGRADE_SHELL" "$SYSUPGRADE" -f "$PACKAGE" \
        >"$log" 2>&1 &
    owner_pid=$!

    lock_wait=0
    while [ ! -f "$SYSUPGRADE_LOCK_DIR/owner" ] && [ "$lock_wait" -lt 200 ]; do
        kill -0 "$owner_pid" 2>/dev/null || break
        sleep 0.05
        lock_wait=$((lock_wait + 1))
    done
    [ -f "$SYSUPGRADE_LOCK_DIR/owner" ] || {
        set +e
        wait "$owner_pid"
        set -e
        cat "$log" >&2
        die "first sysupgrade did not publish its transaction lock"
    }

    if env "${ENV_ARGS[@]}" "$SYSUPGRADE_SHELL" "$SYSUPGRADE" \
        "$WORKDIR/concurrent-package-must-not-be-parsed.tar" \
        >"$concurrent_log" 2>&1; then
        die "concurrent sysupgrade unexpectedly acquired the live transaction lock"
    fi
    grep -Fq 'another sysupgrade transaction is active' "$concurrent_log" || {
        cat "$concurrent_log" >&2
        die "concurrent sysupgrade did not refuse the live transaction owner"
    }

    set +e
    wait "$owner_pid"
    owner_status=$?
    set -e
    [ "$owner_status" -ne 0 ] || \
        die "sysupgrade unexpectedly succeeded with unsafe active credential mode"
    grep -Fq 'unsafe mode 644 for source dashboard credential' "$log" || {
        cat "$log" >&2
        die "persistence failure probe did not reach the unsafe-credential refusal"
    }
    grep -Fq 'Error: active persistent state failed preflight validation.' "$log" || {
        cat "$log" >&2
        die "sysupgrade did not report the persistent-state pre-flip refusal"
    }
    if [ -s "$UBIUPDATEVOL_AUDIT_LOG" ]; then
        cat "$UBIUPDATEVOL_AUDIT_LOG" >&2
        die "persistent-state preflight refusal invoked ubiupdatevol"
    fi
    assert_boot_environment "$SEED_FIRMWARE" 1 no \
        "persistence failure changed the pre-flip boot environment"
    [ ! -e "$SYSUPGRADE_LOCK_DIR" ] && [ ! -L "$SYSUPGRADE_LOCK_DIR" ] || \
        die "failed sysupgrade did not release its transaction lock"
    chmod 0600 /data/dcent/auth.json
    echo "OFFLINE_NANDSIM_CONCURRENT_WRITER_REFUSAL_OK target=$TARGET"
    echo "OFFLINE_NANDSIM_PERSISTENCE_FAILURE_PROOF_OK target=$TARGET ubiupdatevol_calls=0 firmware=$SEED_FIRMWARE upgrade_stage=1 first_boot=no"
}

assert_success_lock_preserved() {
    [ -d "$SYSUPGRADE_LOCK_DIR" ] && [ ! -L "$SYSUPGRADE_LOCK_DIR" ] || \
        die "successful sysupgrade did not preserve its transaction lock"
    [ -f "$SYSUPGRADE_LOCK_DIR/owner" ] && [ ! -L "$SYSUPGRADE_LOCK_DIR/owner" ] || \
        die "successful sysupgrade preserved no safe lock receipt"
    grep -Fq 'schema=dcentos-sysupgrade-lock-v2' "$SYSUPGRADE_LOCK_DIR/owner" || \
        die "successful sysupgrade lock receipt has the wrong schema"
    grep -Fq 'owner=zynq-sysupgrade' "$SYSUPGRADE_LOCK_DIR/owner" || \
        die "successful sysupgrade lock receipt has the wrong owner kind"
    [ "$(grep -c '^phase=env-committed$' "$SYSUPGRADE_LOCK_DIR/owner")" = 1 ] || \
        die "successful sysupgrade lock receipt is not exactly phase=env-committed"
    echo "OFFLINE_NANDSIM_SUCCESS_LOCK_PRESERVED_OK target=$TARGET"
}

verify_written_volume() {
    local label=$1 dev=$2 source=$3 work=$4
    local size expected actual tmp blocks
    size=$(wc -c < "$source" | tr -d '[:space:]')
    expected=$(sha256sum "$source" | awk '{print $1}')
    tmp="$work/readback-$label.bin"
    blocks=$(( (size + 1048575) / 1048576 ))
    [ "$blocks" -gt 0 ] || blocks=1
    dd if="$dev" of="$tmp" bs=1048576 count="$blocks" >/dev/null 2>&1
    actual=$(head -c "$size" "$tmp" | sha256sum | awk '{print $1}')
    [ "$actual" = "$expected" ] || die "$label readback hash mismatch from $dev"
}

verify_persistent_state_after_remount() {
    local mountpoint=$1 mode protected derived session_state

    mkdir -p "$mountpoint"
    mount -t ubifs -o ro ubi1:rootfs_data "$mountpoint"
    INACTIVE_VERIFY_MOUNTED=1
    path_is_mounted "$mountpoint" || die "inactive rootfs_data read-only mount is not visible"

    # Source the exact helper supplied to the production callers, then add
    # direct fixture assertions so this harness reports concrete credential,
    # dotfile, stale-state, and mode evidence rather than only API success.
    # shellcheck source=/dev/null
    . "$PERSIST_HELPER"
    dcent_persist_verify /data "$mountpoint" || \
        die "persistent-state helper rejected the harness read-only remount"

    cmp -s /data/dcent/auth.json "$mountpoint/dcent/auth.json" || \
        die "dashboard credential bytes differ after read-only remount"
    cmp -s /data/keys/dropbear/dropbear_ed25519_host_key \
        "$mountpoint/keys/dropbear/dropbear_ed25519_host_key" || \
        die "SSH host-key bytes differ after read-only remount"
    cmp -s /data/keys/.key-policy "$mountpoint/keys/.key-policy" || \
        die "hidden key state differs after read-only remount"
    cmp -s /data/config/.fleet.json "$mountpoint/config/.fleet.json" || \
        die "hidden config state differs after read-only remount"
    cmp -s /data/profiles/.factory-calibration \
        "$mountpoint/profiles/.factory-calibration" || \
        die "hidden profile state differs after read-only remount"
    cmp -s /data/dcent/.identity "$mountpoint/dcent/.identity" || \
        die "hidden dashboard state differs after read-only remount"

    [ ! -e "$mountpoint/dcentos-compat" ] && [ ! -L "$mountpoint/dcentos-compat" ] || \
        die "stale inactive dcentos-compat survived without an active source"
    for derived in dcentrald dcentrald-env dcentrald_standalone_boot.sh \
        dcentrald.toml.mgmt-bak; do
        [ ! -e "$mountpoint/$derived" ] && [ ! -L "$mountpoint/$derived" ] || \
            die "runtime-derived state survived persistence staging: $derived"
    done
    [ ! -e "$mountpoint/overlay/etc/upper/stale.conf" ] || \
        die "stale inactive overlay state survived persistence staging"
    [ ! -e "$mountpoint/overlay/etc/upper/.slot-local" ] || \
        die "active slot-local overlay state was incorrectly migrated"
    # Successful sysupgrade is admitted only from an operator-resolved active
    # state.  All three files below were deliberately stale on the inactive
    # slot and must be removed by exact replacement.  Cross-slot preservation
    # of active unresolved/crash evidence is covered directly by the shared
    # persistent-helper regression, never by this successful caller path.
    for session_state in dcentrald-hardware-session.unresolved \
        dcentrald-hardware-session.crash-latched \
        .dcentrald-session-latch.lock; do
        [ ! -e "$mountpoint/dcent/$session_state" ] && \
            [ ! -L "$mountpoint/dcent/$session_state" ] || \
            die "stale inactive hardware-session state was resurrected: $session_state"
    done
    if grep -Fq 'STALE-INACTIVE' "$mountpoint/dcent/auth.json" \
        "$mountpoint/keys/dropbear/dropbear_ed25519_host_key"; then
        die "stale inactive credentials survived persistence staging"
    fi
    [ "$(stat -c '%s' "$mountpoint/keys/random-seed")" = 512 ] || \
        die "fresh inactive entropy seed is not 512 bytes"
    mode=$(stat -c '%a' "$mountpoint/keys/random-seed")
    [ "$mode" = 600 ] || die "fresh inactive entropy seed mode=$mode, expected 600"
    cmp -s /data/keys/random-seed "$mountpoint/keys/random-seed" && \
        die "inactive slot reused the active entropy seed"

    mode=$(stat -c '%a' "$mountpoint/dcent")
    [ "$mode" = 700 ] || die "dashboard state mode=$mode after remount, expected 700"
    for protected in \
        "$mountpoint/dcent/auth.json" \
        "$mountpoint/dcent/authorized_keys" \
        "$mountpoint/keys/dropbear/authorized_keys" \
        "$mountpoint/keys/dropbear/dropbear_ed25519_host_key"; do
        mode=$(stat -c '%a' "$protected")
        [ "$mode" = 600 ] || die "protected persistent file $protected mode=$mode, expected 600"
    done
    mode=$(stat -c '%a' "$mountpoint/overlay/etc/upper")
    [ "$mode" = 700 ] || die "inactive overlay upper mode=$mode, expected 700"
    mode=$(stat -c '%a' "$mountpoint/overlay/etc/work")
    [ "$mode" = 700 ] || die "inactive overlay work mode=$mode, expected 700"
    if touch "$mountpoint/.read-only-probe" 2>/dev/null; then
        rm -f "$mountpoint/.read-only-probe"
        die "inactive rootfs_data accepted a write after read-only remount"
    fi

    umount "$mountpoint"
    INACTIVE_VERIFY_MOUNTED=0
    rmdir "$mountpoint"
}

probe_capabilities() {
    need_root
    for tool in awk basename cat chmod chown cmp cp dd find grep head id mkenvimage mkdir mkfs.ubifs mktemp mknod modprobe mount \
        kill mv readlink rm rmdir sed sha256sum sleep sort stat sync tar touch tr umount wc \
        flash_erase nandwrite ubidetach ubiformat ubiattach ubimkvol ubiupdatevol fw_printenv fw_setenv; do
        need_tool "$tool"
    done
    load_ubi_module
    load_module ubifs
    load_nandsim
}

probe_geometry_capabilities() {
    need_root
    for tool in awk cat grep id modprobe ubidetach ubiformat ubiattach; do
        need_tool "$tool"
    done
    load_ubi_module
    load_module ubifs
    load_nandsim
}

# --- CE-026: resolve A/B direction (default forward = today's behavior) ---
# Forward (current-fw=2) mounts active mtd8 as ubi0 and targets inactive mtd7.
# Reverse (current-fw=1) mounts active mtd7 as ubi0, targets inactive mtd8, and
# expects a post-flip firmware=2 / upgrade_stage=0.
case "$CURRENT_FW" in
    2)
        DIRECTION=forward
        SEED_FIRMWARE=2
        EXPECTED_POSTFLIP_FIRMWARE=1
        CMDLINE_UBI_MTD=8
        ;;
    1)
        DIRECTION=reverse
        NANDSIM_PARTS=$NANDSIM_PARTS_REVERSE
        NANDSIM_INACTIVE_MTD=8
        SEED_FIRMWARE=1
        EXPECTED_POSTFLIP_FIRMWARE=2
        CMDLINE_UBI_MTD=7
        ;;
    *)
        die "--current-fw must be 1 or 2 (got '$CURRENT_FW')"
        ;;
esac

if [ "$PROBE_ONLY" = 1 ] && [ "$GEOMETRY_ONLY" = 1 ]; then
    die "--probe-only and --geometry-only are mutually exclusive"
fi

if [ "$PROBE_ONLY" = 1 ]; then
    dcent_zynq_nandsim_profile_select capability-only || \
        die "cannot select capability-only nandsim profile"
elif [ "$GEOMETRY_ONLY" = 1 ]; then
    case "$TARGET" in
        am2-s17pro|am2-s19jpro|am2-s19pro) ;;
        *) die "--geometry-only requires an AM2 target" ;;
    esac
    dcent_zynq_nandsim_profile_select "$TARGET" || \
        die "unsupported nandsim target '$TARGET'"
    [ "$DCENT_ZYNQ_NANDSIM_GEOMETRY_AUTHORITY" = am2-live-exact ] || \
        die "--geometry-only did not select AM2 live geometry authority"
else
    [ -n "$TARGET" ] || die "--target is required"
    [ -n "$PACKAGE" ] || die "--package is required"
    [ -n "$WORKDIR" ] || die "--workdir is required"
    [ -f "$PACKAGE" ] || die "package not found: $PACKAGE"
    dcent_zynq_nandsim_profile_select "$TARGET" || \
        die "unsupported nandsim target '$TARGET'"
fi
NANDSIM_PARTS=$DCENT_ZYNQ_NANDSIM_PARTS
NANDSIM_PARTS_REVERSE=$DCENT_ZYNQ_NANDSIM_PARTS

if [ "${DCENT_SYSUPGRADE_OFFLINE_CONTAINER:-0}" != "1" ]; then
    skip_unavailable "refusing module/device mutation outside a disposable container/VM; set DCENT_SYSUPGRADE_OFFLINE_CONTAINER=1 only inside that environment"
fi
trap cleanup EXIT

if [ "$GEOMETRY_ONLY" = "1" ]; then
    probe_geometry_capabilities
else
    probe_capabilities
fi
if [ "$PROBE_ONLY" = "1" ]; then
    echo "NANDSIM_PROBE_OK: kernel modules and userspace tools are available geometry=functional-only"
    exit 0
fi
if [ "$GEOMETRY_ONLY" = "1" ]; then
    MTD_NUM=$(find_nandsim_mtd)
    [ "$MTD_NUM" = "$NANDSIM_INACTIVE_MTD" ] || \
        die "geometry-only nandsim slot is mtd$MTD_NUM, expected mtd$NANDSIM_INACTIVE_MTD"
    format_nandsim_mtd "$MTD_NUM"
    attach_nandsim_mtd "$MTD_NUM" 1
    ATTACHED_MTD=$(cat /sys/class/ubi/ubi1/mtd_num)
    [ "$ATTACHED_MTD" = "$MTD_NUM" ] || \
        die "geometry-only ubi1 attachment drifted to mtd$ATTACHED_MTD"
    PEB=$(cat "/sys/class/mtd/mtd$MTD_NUM/erasesize")
    LEB=$(cat /sys/class/ubi/ubi1/eraseblock_size)
    TOTAL=$(cat /sys/class/ubi/ubi1/total_eraseblocks)
    RESERVED=$(cat /sys/class/ubi/ubi1/reserved_for_bad)
    BAD=$(cat /sys/class/ubi/ubi1/bad_peb_count)
    AVAILABLE=$(cat /sys/class/ubi/ubi1/avail_eraseblocks)
    ubidetach -d 1 >/dev/null
    echo "OFFLINE_NANDSIM_GEOMETRY_PROOF_OK target=$TARGET mtd=$MTD_NUM authority=$DCENT_ZYNQ_NANDSIM_GEOMETRY_AUTHORITY peb=$PEB leb=$LEB total=$TOTAL reserved_for_bad=$RESERVED bad=$BAD available=$AVAILABLE"
    exit 0
fi

PACKAGE_SOURCE=$PACKAGE
REQUESTED_WORKDIR=$WORKDIR
case "$REQUESTED_WORKDIR" in
    /tmp/dcent-nandsim-*) ;;
    *) die "--workdir must be a direct /tmp/dcent-nandsim-* disposable base" ;;
esac
WORKDIR_NAME=${REQUESTED_WORKDIR#/tmp/}
case "$WORKDIR_NAME" in
    ""|*/*) die "--workdir contains an unsafe disposable-base name" ;;
esac
printf '%s\n' "$WORKDIR_NAME" | grep -Eq '^[A-Za-z0-9._-]+$' || \
    die "--workdir contains an unsafe disposable-base name: '$WORKDIR_NAME'"
if [ -e "$REQUESTED_WORKDIR" ] || [ -L "$REQUESTED_WORKDIR" ]; then
    die "--workdir base must not already exist: $REQUESTED_WORKDIR"
fi
mkdir -m 0700 "$REQUESTED_WORKDIR" || die "cannot create harness-owned workdir base"
REQUESTED_WORKDIR_REAL=$(CDPATH='' cd -P "$REQUESTED_WORKDIR" 2>/dev/null && pwd -P) || \
    die "cannot canonicalize harness-owned workdir base"
[ "$REQUESTED_WORKDIR_REAL" = "$REQUESTED_WORKDIR" ] || \
    die "harness-owned workdir base escaped canonical /tmp containment"
WORKDIR=$(mktemp -d "$REQUESTED_WORKDIR/run.XXXXXX") || \
    die "cannot create harness-owned workdir child"
case "$WORKDIR" in
    "$REQUESTED_WORKDIR"/run.*) ;;
    *) die "mktemp workdir escaped its harness-owned base" ;;
esac

# A host/9p bind mount does not model the production intake boundary: its uid,
# gid, mode, and ancestors belong to the VM transport.  Copy the exact bytes
# into a newly-created root-owned, non-writable staging tree so the real
# sysupgrade package-input admission sees the same trust properties as an
# upload created by the root daemon or scp as root.  This normalizes evidence;
# it does not weaken or bypass the deployed helper.
TRUSTED_PACKAGE_DIR="$WORKDIR/sysupgrade-input"
TRUSTED_PACKAGE="$TRUSTED_PACKAGE_DIR/package.tar"
mkdir -m 0700 "$TRUSTED_PACKAGE_DIR" || die "cannot create trusted package staging directory"
cp -- "$PACKAGE_SOURCE" "$TRUSTED_PACKAGE" || die "cannot stage package from host/9p input"
chown 0:0 "$TRUSTED_PACKAGE" || die "cannot bind staged package ownership to root:root"
chmod 0600 "$TRUSTED_PACKAGE" || die "cannot bind staged package mode to 0600"
cmp -s "$PACKAGE_SOURCE" "$TRUSTED_PACKAGE" || die "trusted package staging copy differs from host input"
[ "$(stat -c '%u:%g:%a:%h:%F' "$TRUSTED_PACKAGE")" = '0:0:600:1:regular file' ] || \
    die "trusted staged package metadata is not root:root 0600 one-link regular-file"
PACKAGE=$TRUSTED_PACKAGE

SYSUPGRADE=$(sysupgrade_path_for_target "$TARGET")
[ -f "$SYSUPGRADE" ] || die "sysupgrade script not found: $SYSUPGRADE"
[ -r "$PERSIST_HELPER" ] || die "persistent-state helper not found: $PERSIST_HELPER"
    [ -r "$TRANSACTION_LOCK_HELPER" ] || \
        die "sysupgrade transaction-lock helper not found: $TRANSACTION_LOCK_HELPER"
    [ -r "$TRANSACTION_WORKSPACE_HELPER" ] || \
        die "sysupgrade transaction-workspace helper not found: $TRANSACTION_WORKSPACE_HELPER"
[ -r "$PACKAGE_INPUT_HELPER" ] || \
    die "sysupgrade package-input helper not found: $PACKAGE_INPUT_HELPER"
[ -r "$ARCHIVE_ADMISSION_HELPER" ] || \
    die "sysupgrade archive-admission helper not found: $ARCHIVE_ADMISSION_HELPER"
[ -r "$SESSION_LATCH_HELPER" ] || \
    die "hardware-session latch helper not found: $SESSION_LATCH_HELPER"
[ -r "$UBI_IDENTITY_HELPER" ] || \
    die "UBI identity helper not found: $UBI_IDENTITY_HELPER"
[ -r "$UBOOT_ENV_ADMISSION_HELPER" ] || \
    die "U-Boot environment admission helper not found: $UBOOT_ENV_ADMISSION_HELPER"

BOARD=$(coarse_board_for_target "$TARGET")
read -r KERNEL_LEBS ROOTFS_LEBS DATA_LEBS < <(volume_lebs_for_target "$TARGET")

CMDLINE_FILE="$WORKDIR/proc_cmdline"
BOARD_FILE="$WORKDIR/board_target"
MARKER_FILE="$WORKDIR/offline_harness.marker"
SHIM_DIR="$WORKDIR/shims"
PAYLOAD_DIR="$WORKDIR/pkg"
VERSION_FILE="$WORKDIR/dcentos-version"
INACTIVE_SEED_MOUNT="$WORKDIR/inactive-data-seed"
INACTIVE_VERIFY_MOUNT="$WORKDIR/inactive-data-readonly"
CALLER_PERSIST_MOUNT="$WORKDIR/caller-inactive-data"
PERSIST_FAILURE_LOG="$WORKDIR/persistence-preflip-failure.log"
CONCURRENT_REFUSAL_LOG="$WORKDIR/concurrent-writer-refusal.log"
SESSION_INTERLOCK_LOG="$WORKDIR/session-interlock-refusal.log"
UBIUPDATEVOL_AUDIT_LOG="$WORKDIR/ubiupdatevol-audit.log"
FAKE_PROC_ROOT="$WORKDIR/proc"
BOOT_ID_FILE="$WORKDIR/boot_id"
OFFLINE_FW_ENV_CONFIG="$WORKDIR/fw_env.config"
OFFLINE_UBOOT_ENV_PROC_MTD="$WORKDIR/proc_mtd"
OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT="$WORKDIR/sys/class/mtd"
SYSUPGRADE_LOCK_DIR="$WORKDIR/sysupgrade-transaction.lock"
SYSUPGRADE_SHELL="$SHIM_DIR/sysupgrade-shell"

printf 'console=ttyPS0 ubi.mtd=%s root=ubi0:rootfs\n' "$CMDLINE_UBI_MTD" >"$CMDLINE_FILE"
printf '%s\n' "$BOARD" >"$BOARD_FILE"
printf 'dcent-sysupgrade-offline-nandsim-harness-v1\n' >"$MARKER_FILE"
mkdir -p "$SHIM_DIR"
cat >"$SHIM_DIR/reboot" <<'EOF'
#!/bin/sh
echo "OFFLINE_HARNESS_REBOOT_SHADOWED"
exit 0
EOF
chmod 0755 "$SHIM_DIR/reboot"
REAL_UBIUPDATEVOL=$(command -v ubiupdatevol)
[ -n "$REAL_UBIUPDATEVOL" ] || skip_unavailable "cannot resolve the real ubiupdatevol"
cat >"$SHIM_DIR/ubiupdatevol" <<'EOF'
#!/bin/sh
set -eu
: "${DCENT_SYSUPGRADE_REAL_UBIUPDATEVOL:?}"
: "${DCENT_SYSUPGRADE_UBIUPDATEVOL_AUDIT_LOG:?}"
printf '%s\n' "$*" >>"$DCENT_SYSUPGRADE_UBIUPDATEVOL_AUDIT_LOG"
exec "$DCENT_SYSUPGRADE_REAL_UBIUPDATEVOL" "$@"
EOF
chmod 0755 "$SHIM_DIR/ubiupdatevol"
mkdir -p "$FAKE_PROC_ROOT"
printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' >"$BOOT_ID_FILE"
cat >"$SYSUPGRADE_SHELL" <<'EOF'
#!/bin/sh
set -eu
proc_root=${DCENT_SYSUPGRADE_PROC_ROOT:?}
pid=$$
starttime=$((1000000 + pid))
mkdir -p "$proc_root/$pid"
line="$pid (dcent-sysupgrade) S"
field=1
while [ "$field" -le 18 ]; do
    line="$line 0"
    field=$((field + 1))
done
printf '%s %s 0\n' "$line" "$starttime" >"$proc_root/$pid/stat"
chmod 0444 "$proc_root/$pid/stat"
exec /bin/sh "$@"
EOF
chmod 0755 "$SYSUPGRADE_SHELL"

PREFIX=$BOARD
PAYLOAD_SUBDIR=$(extract_package_payloads "$PACKAGE" "$PAYLOAD_DIR" "$PREFIX")
PACKAGE_VERSION=$(package_manifest_version "$PAYLOAD_SUBDIR/MANIFEST.json")
[ -n "$PACKAGE_VERSION" ] || die "package manifest missing version for offline sysupgrade fixture"
printf '%s\n' "$PACKAGE_VERSION" >"$VERSION_FILE"

MTD_NUM=$(create_nandsim_mtd)
[ "$MTD_NUM" = "$NANDSIM_INACTIVE_MTD" ] || die "nandsim inactive MTD is mtd$MTD_NUM; direction=$DIRECTION expects mtd$NANDSIM_INACTIVE_MTD from ubi.mtd=$CMDLINE_UBI_MTD"
prepare_inactive_ubi "$MTD_NUM" "$TARGET" "$KERNEL_LEBS" "$ROOTFS_LEBS" "$DATA_LEBS" \
    "$PAYLOAD_SUBDIR/kernel" "$PAYLOAD_SUBDIR/root"
prepare_active_data_mount "$CMDLINE_UBI_MTD" "$KERNEL_LEBS" "$ROOTFS_LEBS" "$DATA_LEBS"
seed_stale_inactive_data_fixture "$MTD_NUM" "$INACTIVE_SEED_MOUNT"
seed_fw_env_fixture "$WORKDIR"

ENV_ARGS=(
    "PATH=$SHIM_DIR:$PATH"
    "DCENT_SYSUPGRADE_OFFLINE_HARNESS=1"
    "DCENT_SYSUPGRADE_OFFLINE_MARKER=$MARKER_FILE"
    "DCENT_SYSUPGRADE_PROC_CMDLINE_PATH=$CMDLINE_FILE"
    "DCENT_SYSUPGRADE_BOARD_TARGET_PATH=$BOARD_FILE"
    "DCENT_SYSUPGRADE_VERSION_PATH=$VERSION_FILE"
    "DCENT_SYSUPGRADE_PERSIST_HELPER=$PERSIST_HELPER"
    "DCENT_SYSUPGRADE_PERSIST_SOURCE_ROOT=/data"
    "DCENT_SYSUPGRADE_PERSIST_MOUNT_ROOT=$CALLER_PERSIST_MOUNT"
    "DCENT_SYSUPGRADE_PROC_MOUNTS_PATH=/proc/mounts"
    "DCENT_SYSUPGRADE_TRANSACTION_LOCK_HELPER=$TRANSACTION_LOCK_HELPER"
    "DCENT_SYSUPGRADE_TRANSACTION_WORKSPACE_HELPER=$TRANSACTION_WORKSPACE_HELPER"
    "DCENT_SYSUPGRADE_PACKAGE_INPUT_HELPER=$PACKAGE_INPUT_HELPER"
    "DCENT_SYSUPGRADE_ARCHIVE_ADMISSION_HELPER=$ARCHIVE_ADMISSION_HELPER"
    "DCENT_SYSUPGRADE_SESSION_LATCH_HELPER=$SESSION_LATCH_HELPER"
    "DCENT_SYSUPGRADE_UBI_IDENTITY_HELPER=$UBI_IDENTITY_HELPER"
    "DCENT_SYSUPGRADE_ZYNQ_GEOMETRY_HELPER=$ZYNQ_GEOMETRY_HELPER"
    "DCENT_SYSUPGRADE_UBOOT_ENV_ADMISSION_HELPER=$UBOOT_ENV_ADMISSION_HELPER"
    "DCENT_SYSUPGRADE_AM2_OTA_HELPER=$AM2_OTA_OFFLINE_STUB"
    "DCENT_SYSUPGRADE_FW_ENV_CONFIG=$OFFLINE_FW_ENV_CONFIG"
    "DCENT_SYSUPGRADE_UBOOT_ENV_PROC_MTD=$OFFLINE_UBOOT_ENV_PROC_MTD"
    "DCENT_SYSUPGRADE_UBOOT_ENV_SYSFS_MTD_ROOT=$OFFLINE_UBOOT_ENV_SYSFS_MTD_ROOT"
    "DCENT_SYSUPGRADE_UBOOT_ENV_MTD4_DEVICE=/dev/mtd4"
    "DCENT_SYSUPGRADE_LOCK_DIR=$SYSUPGRADE_LOCK_DIR"
    "DCENT_SYSUPGRADE_PROC_ROOT=$FAKE_PROC_ROOT"
    "DCENT_SYSUPGRADE_BOOT_ID_PATH=$BOOT_ID_FILE"
    "DCENT_SYSUPGRADE_REAL_UBIUPDATEVOL=$REAL_UBIUPDATEVOL"
    "DCENT_SYSUPGRADE_UBIUPDATEVOL_AUDIT_LOG=$UBIUPDATEVOL_AUDIT_LOG"
)
if [ -n "$RELEASE_KEY" ]; then
    ENV_ARGS+=("DCENT_SYSUPGRADE_RELEASE_PUBKEY=$RELEASE_KEY")
fi
if [ "$ALLOW_LAB_PACKAGE" = "1" ]; then
    ENV_ARGS+=("DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1" "DCENT_PACKAGE_STATUS=lab")
fi

run_session_interlock_failure_probe "$SESSION_INTERLOCK_LOG"
run_persistence_preflip_failure_probe "$PERSIST_FAILURE_LOG" "$CONCURRENT_REFUSAL_LOG"
env "${ENV_ARGS[@]}" "$SYSUPGRADE_SHELL" "$SYSUPGRADE" -f "$PACKAGE"
assert_success_lock_preserved

attach_nandsim_mtd "$MTD_NUM" 1
create_ubi_device_nodes
verify_written_volume kernel /dev/ubi1_0 "$PAYLOAD_SUBDIR/kernel" "$WORKDIR"
verify_written_volume rootfs /dev/ubi1_1 "$PAYLOAD_SUBDIR/root" "$WORKDIR"
verify_persistent_state_after_remount "$INACTIVE_VERIFY_MOUNT"

assert_boot_environment "$EXPECTED_POSTFLIP_FIRMWARE" 0 yes \
    "successful sysupgrade boot-selector verification failed"
run_first_boot_readback_negative_probes

ubidetach -d 1 >/dev/null 2>&1 || true
# Repeat this gated result in the stable final summary.  Early virtme serial
# output can interleave with delayed UBI/kernel messages even though the proof
# function completed successfully.
echo "OFFLINE_NANDSIM_SESSION_INTERLOCK_PROOF_OK target=$TARGET ubiupdatevol_calls=0 firmware=$SEED_FIRMWARE upgrade_stage=1 first_boot=no final_summary=yes"
if [ "$DIRECTION" = "reverse" ]; then
    echo "OFFLINE_NANDSIM_PROOF_OK target=$TARGET direction=reverse current_fw=1 inactive_mtd=8 mtd=$MTD_NUM geometry=$DCENT_ZYNQ_NANDSIM_GEOMETRY_AUTHORITY scope=write-path-only boot_commit_proof=no package=$PACKAGE"
else
    echo "OFFLINE_NANDSIM_PROOF_OK target=$TARGET mtd=$MTD_NUM geometry=$DCENT_ZYNQ_NANDSIM_GEOMETRY_AUTHORITY scope=write-path-only boot_commit_proof=no package=$PACKAGE"
fi
