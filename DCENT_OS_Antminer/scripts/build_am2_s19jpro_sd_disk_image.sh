#!/usr/bin/env bash
#
# build_am2_s19jpro_sd_disk_image.sh — Build a flashable .img for the
# Antminer S19j Pro Zynq am2 control board (am2-s19jpro variant, XIL-class
# unit including Loki-modded APW3 + Loki-board passthrough).
#
# This script creates a regular disk image with a small FAT16 boot partition
# (FSBL + U-Boot + bitstream), the DCENT_OS rootfs squashfs written RAW as
# partition 2 (the squashfs IS the root — the kernel mounts it read-only,
# exactly the proven .25/.109 NAND runtime model), and a small ext2 /data
# partition 3 carrying the XIL quiet config + handoff helpers. It never
# writes to a block device — the physical SD write remains an explicit
# operator action with dd, Rufus, or balenaEtcher.
#
# *** 2026-06-10 SD BOOT DEFECT FIX (squashfs-root model) ***
# The previous revision made p2 an ext2 filesystem holding
# /dcentos/rootfs.squashfs as a FILE and booted root=/dev/mmcblk0p2
# rootfstype=ext2 with `bootm ${kloadaddr} - ${fdtaddr}` (no initramfs).
# The kernel mounted that ext2 (no /sbin/init) -> "No init found" panic ->
# boot loop. The PROVEN model (how .25/.109 actually run DCENT_OS from
# NAND): the squashfs IS the root, mounted ro by the kernel — see
# br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-early-init.sh:12
# and  p2 is now
# the RAW squashfs and bootargs use rootfstype=squashfs ro rootwait.
#
# Modelled after `build_am3_bb_sd_disk_image.sh`. Per the DevOps Q1 report
# ( finding #1), the per-SoC
# stage list is:
#   FSBL  -> BraiinsOS am1-s9 BOOT.bin (carries the proven s9-io-am2
#            bitstream — same chain UART register layout exercised by the
#            2026-05-15 first-accepted-shares milestone on .109)
#   uImage -> BraiinsOS kernel 4.4.92 (Cortex-A9 + xilinx ABI)
#   DTB    -> S19j Pro Zynq am2 device tree
#   squashfs rootfs -> DCENT_OS rootfs, RAW as partition 2 (root device)
#
# Partitioning: MBR + p1 FAT16 boot + p2 RAW squashfs root + p3 ext2 /data.
#
# *** DO NOT attempt to reuse the stock XIL `BOOT.BIN` payload ***
#,
# the stock XIL `BOOT.bin` is RSA-2048 signed and eFuse-gated. Swapping the
# kernel/DTB/initrd inside the signed BOOT.bin payload will be rejected by
# the XIL loader. DCENT_OS SD boot must use the BraiinsOS `boot.bin` +
# `u-boot.img` chain (which load BEFORE the stock signature gate arms).
#
# Inputs:
#   --payload-tar <tar>      DCENT_OS am2-s19jpro sysupgrade tarball, e.g.
#                            DCENT_OS_Antminer/output/dcentos-sysupgrade-am2-s19jpro.tar
#                            (script extracts the rootfs squashfs from inside
#                            the sysupgrade-am2-s19j/ payload).
#   --payload-dir <dir>      Exact target-bound sysupgrade-am2-s19j payload
#                            directory, including target manifest and hashes.
#   --artifacts <dir>        Required unless --allow-incomplete. Exact output
#                            of stage_am2_sd_artifacts.py: artifacts.manifest.json,
#                            BOOT.bin, uImage, system.bit, and devicetree.dtb.
#   --bitstream <file>       Optional explicit bitstream override. Defaults
#                            to
#                            (the proven 2026-05-15 path). The file is staged
#                            into the rootfs (legacy compat) AND onto the boot
#                            partition for U-Boot fpga load.
#   --xil-config <toml>      Optional idle-first TOML override, staged on the
#                            SD data partition. Defaults to the baked-safe
#                            dcentrald_s19jpro_xil_baked_default.toml.
#   --size-mb N              Total .img size (default 256, auto-grown).
#   --allow-incomplete       Build a known-nonbootable rootfs-only lab artifact.
#
# Output:
#   DCENT_OS_Antminer/buildroot/output/images/sd_card_am2_s19jpro/dcentos-am2-s19jpro.img

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"
# shellcheck source=lib/sd_common.sh
. "$SCRIPT_DIR/lib/sd_common.sh"
BUILDROOT_OUTPUT="${BUILDROOT_OUTPUT:-$PROJECT_DIR/buildroot/output/images}"
SD_OUTPUT_DIR="$BUILDROOT_OUTPUT/sd_card_am2_s19jpro"
ARTIFACT_DIR=""
PAYLOAD_TAR=""
PAYLOAD_DIR=""
BITSTREAM_OVERRIDE=""
XIL_CONFIG_OVERRIDE=""
ALLOW_INCOMPLETE=0
DISK_IMAGE_SIZE_MB=256
TOOLBOX_BUILD_TOKEN=""
VALIDATE_INPUTS_ONLY=0
IDLE_FIRST_VALIDATED=0
ARTIFACT_STAGE_MANIFEST=""
# Use the library's shared cleanup array under a local-friendly alias so
# inline `CLEANUP_PATHS+=("$tmp")` continues to work. The library owns the
# EXIT/INT/TERM trap that walks the array.
declare -n CLEANUP_PATHS=SD_COMMON_CLEANUP_PATHS
sd_common::install_cleanup_trap

usage() {
    cat <<EOF
Usage: $(basename "$0") [--payload-tar <tar>|--payload-dir <dir>] --artifacts <dir> [--size-mb N]
                       [--bitstream <file>] [--xil-config <toml>] [--allow-incomplete]

Options:
  --artifacts <dir>   Exact target-bound output of stage_am2_sd_artifacts.py.
                      Required unless --allow-incomplete.
  --payload-tar <tar> Exact DCENT_OS am2-s19jpro sysupgrade tarball.
  --payload-dir <dir> Exact target-bound sysupgrade-am2-s19j payload directory.
  --bitstream <file>  FPGA bitstream override (default: knowledge-base
                      s9-io-am2 .bit). NEVER substitute the stock XIL
                      Anthill bitstream — the dcentrald chain UART register
                      offsets target the BraiinsOS s9-io-am2 IP.
  --xil-config <toml> Idle-first dcentrald_s19jpro_xil.toml override.
  --size-mb N         Total .img size (default ${DISK_IMAGE_SIZE_MB}, auto-grown).
  --allow-incomplete  Build a known-nonbootable rootfs-only lab artifact.
  --toolbox-build-token HEX
                      Internal freshness token supplied by DCENT_Toolbox.
  --validate-inputs-only
                      Validate exact local inputs; create no image.
  -h, --help          Show this help.

Output: $SD_OUTPUT_DIR/dcentos-am2-s19jpro.img

Safety:
  - Refuses to write to a block device path.
  - Refuses a stock signed XIL BOOT.bin, which cannot chain substituted
    kernel/DTB payloads; all boot inputs must be hash-bound by the stage manifest.
  - Validates the rootfs squashfs is at least 8 MB before staging.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --artifacts)
            ARTIFACT_DIR="${2:?--artifacts requires a path}"
            shift 2
            ;;
        --artifacts=*)
            ARTIFACT_DIR="${1#--artifacts=}"
            shift
            ;;
        --payload-tar)
            PAYLOAD_TAR="${2:?--payload-tar requires a path}"
            shift 2
            ;;
        --payload-tar=*)
            PAYLOAD_TAR="${1#--payload-tar=}"
            shift
            ;;
        --payload-dir)
            PAYLOAD_DIR="${2:?--payload-dir requires a path}"
            shift 2
            ;;
        --payload-dir=*)
            PAYLOAD_DIR="${1#--payload-dir=}"
            shift
            ;;
        --bitstream)
            BITSTREAM_OVERRIDE="${2:?--bitstream requires a path}"
            shift 2
            ;;
        --bitstream=*)
            BITSTREAM_OVERRIDE="${1#--bitstream=}"
            shift
            ;;
        --xil-config)
            XIL_CONFIG_OVERRIDE="${2:?--xil-config requires a path}"
            shift 2
            ;;
        --xil-config=*)
            XIL_CONFIG_OVERRIDE="${1#--xil-config=}"
            shift
            ;;
        --size-mb)
            DISK_IMAGE_SIZE_MB="${2:?--size-mb requires N}"
            shift 2
            ;;
        --size-mb=*)
            DISK_IMAGE_SIZE_MB="${1#--size-mb=}"
            shift
            ;;
        --allow-incomplete)
            ALLOW_INCOMPLETE=1
            shift
            ;;
        --toolbox-build-token)
            TOOLBOX_BUILD_TOKEN="${2:?--toolbox-build-token requires a value}"
            shift 2
            ;;
        --toolbox-build-token=*)
            TOOLBOX_BUILD_TOKEN="${1#--toolbox-build-token=}"
            shift
            ;;
        --validate-inputs-only)
            VALIDATE_INPUTS_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -n "$TOOLBOX_BUILD_TOKEN" ]; then
    case "$TOOLBOX_BUILD_TOKEN" in
        *[!0-9a-f]*)
            echo "ERROR: --toolbox-build-token must be lowercase hexadecimal" >&2
            exit 1
            ;;
    esac
    if [ "${#TOOLBOX_BUILD_TOKEN}" -ne 64 ]; then
        echo "ERROR: --toolbox-build-token must contain exactly 64 hexadecimal characters" >&2
        exit 1
    fi
fi

sd_common::refuse_block_device "$SD_OUTPUT_DIR"

mkdir -p "$SD_OUTPUT_DIR"

# Thin shim wrappers around sd_common::* — preserved so existing inline
# callers continue to work without churning every call site.
need_tool() { sd_common::need_tool "$@"; }
total_bytes() { sd_common::total_bytes "$@"; }
PYTHON=""

ensure_python() {
    [ -n "$PYTHON" ] && return 0
    for python_candidate in python3 python; do
        if command -v "$python_candidate" >/dev/null 2>&1 &&
           "$python_candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
            PYTHON="$python_candidate"
            return 0
        fi
    done
    echo "ERROR: Python 3.9 or newer is required for typed AM2 input admission" >&2
    exit 1
}

file_sha256_or_empty() {
    if [ -n "${1:-}" ] && [ -f "$1" ]; then
        sha256sum "$1" | awk '{print $1}'
    else
        printf ''
    fi
}

extract_toml_value() { # $1=file  $2=section (no brackets)  $3=key
    awk -v sect="[$2]" -v key="$3" '
        /^[[:space:]]*\[/ {
            hdr = $0; gsub(/[[:space:]]/, "", hdr)
            in_sect = (hdr == sect) ? 1 : 0
            next
        }
        in_sect && $0 ~ ("^[[:space:]]*" key "[[:space:]]*=") {
            sub(/^[^=]*=[[:space:]]*/, "", $0)
            sub(/[[:space:]]*#.*$/, "", $0)
            # Preserve spaces inside quoted values: they are part of the value.
            sub(/[[:space:]]*$/, "", $0)
            print $0
            exit
        }
    ' "$1"
}

require_toml_value() { # $1=file $2=section $3=key $4=expected
    config_file="$1"
    config_section="$2"
    config_key="$3"
    config_expected="$4"
    config_actual=$(extract_toml_value "$config_file" "$config_section" "$config_key")
    if [ "$config_actual" != "$config_expected" ]; then
        echo "ERROR: unsafe XIL config [$config_section] $config_key='${config_actual:-unset}', expected '$config_expected'" >&2
        exit 1
    fi
}

assert_idle_first_config() {
    config_file="$1"
    [ -f "$config_file" ] && [ ! -L "$config_file" ] || {
        echo "ERROR: a regular non-symlink XIL config is required for idle-first media" >&2
        exit 1
    }
    require_toml_value "$config_file" mining enabled false
    # The generic override still supports retained handoff configurations.
    # Check an explicitly declared origin without inventing a cold recipe.
    config_boot_origin=$(extract_toml_value "$config_file" mining am2_boot_origin)
    case "$config_boot_origin" in
        ''|'"inherited_handoff"'|"'inherited_handoff'") ;;
        '"native_cold"'|"'native_cold'")
            config_passthrough=$(extract_toml_value "$config_file" mining passthrough)
            case "$config_passthrough" in
                ''|false) ;; # The daemon defaults an absent passthrough to false.
                *)
                    echo "ERROR: XIL config [mining] am2_boot_origin=native_cold conflicts with passthrough='$config_passthrough'" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "ERROR: unrecognized XIL config [mining] am2_boot_origin='$config_boot_origin'" >&2
            exit 1
            ;;
    esac
    require_toml_value "$config_file" pool url '""'
    require_toml_value "$config_file" pool worker '""'
    require_toml_value "$config_file" power.psu_override enabled true
    require_toml_value "$config_file" power.psu_override model '"APW3"'
    require_toml_value "$config_file" power.psu_override voltage_v 12.8
    require_toml_value "$config_file" watchdog enabled true
    require_toml_value "$config_file" hash_on_disconnect enabled false
    IDLE_FIRST_VALIDATED=1
}

validate_target_payload_dir() {
    payload_root="$1"
    payload_manifest="$payload_root/MANIFEST.json"
    payload_sums="$payload_root/SHA256SUMS"
    payload_rootfs="$payload_root/root"
    "$PYTHON" - "$payload_manifest" "$payload_sums" "$payload_rootfs" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys

manifest, sums, rootfs = (Path(value) for value in sys.argv[1:])
for label, path in (("MANIFEST.json", manifest), ("SHA256SUMS", sums), ("root", rootfs)):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size <= 0:
        raise SystemExit(f"ERROR: target payload {label} must be a non-empty regular non-symlink file")

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

raw = manifest.read_bytes()
if len(raw) > 256 * 1024:
    raise SystemExit("ERROR: target payload MANIFEST.json exceeds 256 KiB")
try:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"ERROR: invalid target payload MANIFEST.json: {error}")
expected = {
    "product": "DCENT_OS",
    "package_type": "sysupgrade",
    "board": "am2-s19j",
    "board_target": "am2-s19j",
}
for key, value in expected.items():
    if document.get(key) != value:
        raise SystemExit(f"ERROR: target payload MANIFEST.json {key} mismatch")
payloads = document.get("payloads")
root_record = payloads.get("rootfs") if isinstance(payloads, dict) else None
if not isinstance(root_record, dict):
    raise SystemExit("ERROR: target payload MANIFEST.json lacks rootfs record")
if root_record.get("path") != "sysupgrade-am2-s19j/root":
    raise SystemExit("ERROR: target payload rootfs path is not am2-s19j bound")
PY
    (cd "$payload_root" && sha256sum -c SHA256SUMS >/dev/null) || {
        echo "ERROR: target payload SHA256SUMS verification failed" >&2
        exit 1
    }
}

validate_artifact_stage_manifest() {
    stage_root="$1"
    staged_bitstream="${2:-}"
    stage_manifest="$stage_root/artifacts.manifest.json"
    "$PYTHON" - "$stage_manifest" "$stage_root" "$staged_bitstream" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

manifest = Path(sys.argv[1])
root = Path(sys.argv[2])
bitstream = Path(sys.argv[3]) if sys.argv[3] else None
info = os.lstat(manifest)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size <= 0:
    raise SystemExit("ERROR: artifacts.manifest.json must be a non-empty regular non-symlink file")

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

raw = manifest.read_bytes()
if len(raw) > 1024 * 1024:
    raise SystemExit("ERROR: artifacts.manifest.json exceeds 1 MiB")
try:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"ERROR: invalid artifacts.manifest.json: {error}")
expected = {
    "schema": "dcentos.am2_sd_artifacts_stage.v2",
    "board_target": "am2-s19j",
    "control_board_family": "zynq-bm3-am2",
    "media_target": "am2-s19jpro-sd",
    "provenance_scope": "local-snapshot-integrity-only",
    "ready_for_complete_build": True,
}
for key, value in expected.items():
    if document.get(key) != value:
        raise SystemExit(f"ERROR: artifacts.manifest.json {key} mismatch")
artifacts = document.get("artifacts")
if not isinstance(artifacts, dict):
    raise SystemExit("ERROR: artifacts.manifest.json has no artifact inventory")
names = ["BOOT.bin", "uImage", "devicetree.dtb"]
if bitstream is not None:
    expected_bitstream = root / "system.bit"
    if bitstream.resolve() != expected_bitstream.resolve():
        raise SystemExit("ERROR: --bitstream override must be staged as artifacts/system.bit")
    names.append("system.bit")
for name in names:
    record = artifacts.get(name)
    if not isinstance(record, dict) or record.get("present") is not True:
        raise SystemExit(f"ERROR: artifacts.manifest.json does not admit {name}")
    path = root / name
    current = os.lstat(path)
    if not stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode):
        raise SystemExit(f"ERROR: staged {name} is not a regular non-symlink file")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if record.get("bytes") != current.st_size or record.get("sha256") != digest:
        raise SystemExit(f"ERROR: staged {name} does not match artifacts.manifest.json")
PY
    ARTIFACT_STAGE_MANIFEST="$stage_manifest"
}

json_bool_file() {
    if [ -n "${1:-}" ] && [ -f "$1" ]; then
        printf 'true'
    else
        printf 'false'
    fi
}

json_bool_int() {
    if [ "${1:-0}" -eq 1 ]; then
        printf 'true'
    else
        printf 'false'
    fi
}

write_am2_sd_manifest() {
    manifest_file="$IMG_FILE.manifest.json"
    manifest_boot_bin=$(json_bool_file "$BOOT_BIN_SRC")
    manifest_uimage=$(json_bool_file "$UIMAGE_SRC")
    manifest_dtb=$(json_bool_file "$DTB_SRC")
    manifest_bitstream=$(json_bool_file "$BITSTREAM_SRC")
    manifest_rootfs=$(json_bool_file "$ROOTFS_SQUASHFS")
    manifest_uenv=$(json_bool_int "$UENV_STAGED")
    manifest_allow_incomplete=$(json_bool_int "$ALLOW_INCOMPLETE")
    manifest_image_size=$(total_bytes "$IMG_FILE")
    manifest_image_sha256=$(sha256sum "$IMG_FILE" | awk '{print $1}')
    manifest_stage_size=$(total_bytes "$ARTIFACT_STAGE_MANIFEST")
    manifest_stage_sha=$(file_sha256_or_empty "$ARTIFACT_STAGE_MANIFEST")
    manifest_payload_source_size=$(total_bytes "$PAYLOAD_SOURCE_MANIFEST")
    manifest_payload_source_sha=$(file_sha256_or_empty "$PAYLOAD_SOURCE_MANIFEST")
    manifest_boot_size=$(total_bytes "$BOOT_BIN_SRC")
    manifest_boot_sha=$(file_sha256_or_empty "$BOOT_BIN_SRC")
    manifest_uimage_size=$(total_bytes "$UIMAGE_SRC")
    manifest_uimage_sha=$(file_sha256_or_empty "$UIMAGE_SRC")
    manifest_dtb_size=$(total_bytes "$DTB_SRC")
    manifest_dtb_sha=$(file_sha256_or_empty "$DTB_SRC")
    manifest_bitstream_size=$(total_bytes "$BITSTREAM_SRC")
    manifest_bitstream_sha=$(file_sha256_or_empty "$BITSTREAM_SRC")
    manifest_rootfs_size=$(total_bytes "$ROOTFS_SQUASHFS")
    manifest_rootfs_sha=$(file_sha256_or_empty "$ROOTFS_SQUASHFS")
    manifest_config_size=$(total_bytes "$XIL_CONFIG_SRC")
    manifest_config_sha=$(file_sha256_or_empty "$XIL_CONFIG_SRC")
    manifest_idle_first=$(json_bool_int "$IDLE_FIRST_VALIDATED")

    manifest_complete=false
    if [ "$manifest_boot_bin" = true ] && \
       [ "$manifest_uimage" = true ] && \
       [ "$manifest_dtb" = true ] && \
       [ "$manifest_uenv" = true ] && \
       [ "$manifest_bitstream" = true ] && \
       [ "$manifest_rootfs" = true ]; then
        manifest_complete=true
    fi

    manifest_body=$(cat <<EOF
{
  "schema": "dcentos.am2_s19jpro_sd_image_manifest.v2",
  "target": "am2-s19jpro-sd",
  "board_target": "am2-s19j",
  "control_board_family": "zynq-bm3-am2",
  "install_scope": "external_media_boot",
  "requires_sd_present": true,
  "persistent_install_authorized": false,
  "nand_mutation_authorized": false,
  "build_invocation_token": "$TOOLBOX_BUILD_TOKEN",
  "image": "$(basename "$IMG_FILE")",
  "image_size_bytes": $manifest_image_size,
  "image_sha256": "$manifest_image_sha256",
  "created_utc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "allow_incomplete": $manifest_allow_incomplete,
  "boot_artifacts_complete": $manifest_complete,
  "idle_first": {
    "config_validated": $manifest_idle_first,
    "mining_enabled": false,
    "pool_url_empty": true,
    "pool_worker_empty": true
  },
  "artifact_provenance": {
    "trust_scope": "local-input-integrity-only",
    "boot_artifact_manifest": {"size_bytes": $manifest_stage_size, "sha256": "$manifest_stage_sha"},
    "rootfs_source_manifest": {"size_bytes": $manifest_payload_source_size, "sha256": "$manifest_payload_source_sha"},
    "BOOT.bin": {"size_bytes": $manifest_boot_size, "sha256": "$manifest_boot_sha"},
    "uImage": {"size_bytes": $manifest_uimage_size, "sha256": "$manifest_uimage_sha"},
    "devicetree.dtb": {"size_bytes": $manifest_dtb_size, "sha256": "$manifest_dtb_sha"},
    "system.bit": {"size_bytes": $manifest_bitstream_size, "sha256": "$manifest_bitstream_sha"},
    "rootfs": {"size_bytes": $manifest_rootfs_size, "sha256": "$manifest_rootfs_sha"},
    "xil_config": {"size_bytes": $manifest_config_size, "sha256": "$manifest_config_sha"}
  },
  "artifacts": {
    "BOOT.bin": $manifest_boot_bin,
    "uImage": $manifest_uimage,
    "devicetree.dtb": $manifest_dtb,
    "uEnv.txt": $manifest_uenv,
    "bitstream": $manifest_bitstream,
    "rootfs": $manifest_rootfs
  }
}
EOF
)
    sd_common::emit_manifest_json "$manifest_file" "$manifest_body"
}

# Default bitstream: the 2026-05-15 first-accepted-shares milestone path.
DEFAULT_BITSTREAM="$REPO_ROOT/knowledge-base/extractions/s19j/fpga_bitstream.bit"
BITSTREAM_SRC=""
if [ -n "$BITSTREAM_OVERRIDE" ]; then
    BITSTREAM_SRC="$BITSTREAM_OVERRIDE"
elif [ -f "$DEFAULT_BITSTREAM" ]; then
    BITSTREAM_SRC="$DEFAULT_BITSTREAM"
fi

# Default XIL config: the BRICK-SAFE baked default ([mining] enabled = false,
# empty pool/worker, [power.psu_override] enabled = true for the proven Loki
# + APW3 path). An active-mining config could cold-start hardware as soon as
# p3 is mounted on /data. Staging the baked default keeps an SD boot
# management-only/idle-first (operator opts into mining via wizard). See
# team-E-dtb-data-adversarial.md (2026-06-10 SD boot defect session).
DEFAULT_XIL_CONFIG="$PROJECT_DIR/dcentrald/configs/dcentrald_s19jpro_xil_baked_default.toml"
XIL_CONFIG_SRC=""
if [ -n "$XIL_CONFIG_OVERRIDE" ]; then
    XIL_CONFIG_SRC="$XIL_CONFIG_OVERRIDE"
elif [ -f "$DEFAULT_XIL_CONFIG" ]; then
    XIL_CONFIG_SRC="$DEFAULT_XIL_CONFIG"
fi
if [ -z "$XIL_CONFIG_SRC" ]; then
    echo "ERROR: safe AM2 S19j-Pro baked config is absent; refusing media build" >&2
    exit 1
fi
assert_idle_first_config "$XIL_CONFIG_SRC"

# --- Locate rootfs squashfs ---
ROOTFS_SQUASHFS=""
SD_PAYLOAD_TMP=""
PAYLOAD_SOURCE_MANIFEST=""
if [ -z "$PAYLOAD_TAR" ] && [ -z "$PAYLOAD_DIR" ]; then
    DEFAULT_PAYLOAD_TAR="$BUILDROOT_OUTPUT/dcentos-sysupgrade-am2-s19jpro.tar"
    if [ -f "$DEFAULT_PAYLOAD_TAR" ]; then
        PAYLOAD_TAR="$DEFAULT_PAYLOAD_TAR"
    fi
fi
if [ -n "$PAYLOAD_TAR" ]; then
    [ -f "$PAYLOAD_TAR" ] || {
        echo "ERROR: payload tar not found: $PAYLOAD_TAR" >&2
        exit 1
    }
    ensure_python
    need_tool tar "install tar"
    need_tool sha256sum "install coreutils"
    SD_PAYLOAD_TMP="$(mktemp -d)"
    CLEANUP_PATHS+=("$SD_PAYLOAD_TMP")
    ARCHIVE_ADMISSION_HELPER="$SCRIPT_DIR/lib/sysupgrade_archive_admission.sh"
    [ -r "$ARCHIVE_ADMISSION_HELPER" ] || {
        echo "ERROR: canonical sysupgrade archive admission helper is missing" >&2
        exit 1
    }
    # shellcheck source=lib/sysupgrade_archive_admission.sh
    . "$ARCHIVE_ADMISSION_HELPER"
    dcent_sysupgrade_archive_admit "$PAYLOAD_TAR" "am2-s19j" "$SD_PAYLOAD_TMP" || {
        echo "ERROR: payload tar failed exact am2-s19j archive admission" >&2
        exit 1
    }
    tar -xf "$PAYLOAD_TAR" -C "$SD_PAYLOAD_TMP"
    TARGET_PAYLOAD_DIR="$SD_PAYLOAD_TMP/sysupgrade-am2-s19j"
    validate_target_payload_dir "$TARGET_PAYLOAD_DIR"
    PAYLOAD_SOURCE_MANIFEST="$TARGET_PAYLOAD_DIR/MANIFEST.json"
    ROOTFS_SQUASHFS="$TARGET_PAYLOAD_DIR/root"
elif [ -n "$PAYLOAD_DIR" ]; then
    ensure_python
    need_tool sha256sum "install coreutils"
    TARGET_PAYLOAD_DIR="$PAYLOAD_DIR/sysupgrade-am2-s19j"
    if [ "$(basename "$PAYLOAD_DIR")" = "sysupgrade-am2-s19j" ]; then
        TARGET_PAYLOAD_DIR="$PAYLOAD_DIR"
    fi
    [ -d "$TARGET_PAYLOAD_DIR" ] || {
        echo "ERROR: --payload-dir must contain exact sysupgrade-am2-s19j payload evidence" >&2
        exit 1
    }
    validate_target_payload_dir "$TARGET_PAYLOAD_DIR"
    PAYLOAD_SOURCE_MANIFEST="$TARGET_PAYLOAD_DIR/MANIFEST.json"
    ROOTFS_SQUASHFS="$TARGET_PAYLOAD_DIR/root"
fi

if [ -z "$ROOTFS_SQUASHFS" ]; then
    echo "ERROR: no DCENT_OS am2-s19jpro rootfs squashfs found." >&2
    echo "       Run the am2-s19jpro Buildroot package first, or pass its" >&2
    echo "       exact target-bound --payload-tar / --payload-dir." >&2
    exit 1
fi

ROOTFS_BYTES=$(total_bytes "$ROOTFS_SQUASHFS")
if [ "$ROOTFS_BYTES" -lt $((8 * 1024 * 1024)) ]; then
    echo "ERROR: rootfs squashfs is suspiciously small ($ROOTFS_BYTES bytes): $ROOTFS_SQUASHFS" >&2
    exit 1
fi
sd_common::verify_squashfs_file "$ROOTFS_SQUASHFS"

# --- Locate boot artifacts ---
BOOT_BIN_SRC=""
UBOOT_SRC=""
UIMAGE_SRC=""
DTB_SRC=""
if [ -n "$ARTIFACT_DIR" ]; then
    [ -d "$ARTIFACT_DIR" ] || {
        echo "ERROR: artifact directory not found: $ARTIFACT_DIR" >&2
        exit 1
    }
    # Complete builds consume only the canonical, atomically staged names
    # emitted by stage_am2_sd_artifacts.py. Alias search made it impossible to
    # bind the copied bytes back to one exact local evidence manifest.
    [ -f "$ARTIFACT_DIR/BOOT.bin" ] && BOOT_BIN_SRC="$ARTIFACT_DIR/BOOT.bin"
    [ -f "$ARTIFACT_DIR/u-boot.img" ] && UBOOT_SRC="$ARTIFACT_DIR/u-boot.img"
    [ -f "$ARTIFACT_DIR/uImage" ] && UIMAGE_SRC="$ARTIFACT_DIR/uImage"
    [ -f "$ARTIFACT_DIR/devicetree.dtb" ] && DTB_SRC="$ARTIFACT_DIR/devicetree.dtb"

    # Refuse to ship a stock XIL BOOT.bin. The published stock-XIL boot.bin
    # MD5s (e.g. f2cb2eaaf757c72946113ad13786afa0 for s19pro xil) come from
    # the awesome v1.2.6 firmware and are RSA-signed by the XIL loader.
    # Operator wrote these into --artifacts by accident? Bail loudly.
    if [ -n "$BOOT_BIN_SRC" ]; then
        BOOT_MD5=""
        if command -v md5sum >/dev/null 2>&1; then
            BOOT_MD5=$(md5sum "$BOOT_BIN_SRC" 2>/dev/null | awk '{print $1}')
        fi
        case "$BOOT_MD5" in
            f2cb2eaaf757c72946113ad13786afa0|730a6ad1566376381dee8a59ebab55d6|\
7f100b3b90461e718ac6c1de0eafa888|dbd17ba1a738647540073f29813de92f|\
acb2fcdbcebfcbb71b02f3d0614363ae|6bc79007d45c3b623756523c6ab903ba)
                echo "ERROR: BOOT.bin md5 $BOOT_MD5 matches a known stock XIL signed image." >&2
                echo "       The XIL loader will reject any chained kernel/DTB swap." >&2
                echo "       Use the exact hash-bound staged boot artifact set instead." >&2
                exit 1
                ;;
        esac

        # SPL/BOOT-header-aware validity guard (pass-2 P2-4): a wrong/truncated
        # --artifacts BOOT.bin otherwise ships a silently-dead card. Accept the
        # proven ~78 KB am1-s9 SPL AND a full ~2.5 MB BOOT.BIN; reject empty /
        # truncated / grossly-wrong images. Size-only (no header byte-check) so a
        # valid SPL is never false-failed.
        BOOT_SZ=$(stat -c%s "$BOOT_BIN_SRC" 2>/dev/null || echo 0)
        if [ "$BOOT_SZ" -lt 20000 ] || [ "$BOOT_SZ" -gt 5000000 ]; then
            echo "ERROR: BOOT.bin is $BOOT_SZ bytes — outside the valid Zynq range" >&2
            echo "       (~78 KB am1-s9 SPL .. ~2.5 MB full BOOT.BIN). Likely truncated or wrong;" >&2
            echo "       shipping it would produce a silently-dead card. Re-check --artifacts." >&2
            exit 1
        fi
    fi
fi

if [ "$ALLOW_INCOMPLETE" -ne 1 ]; then
    missing=""
    [ -n "$BOOT_BIN_SRC" ] || missing="$missing BOOT.bin"
    [ -n "$UIMAGE_SRC" ] || missing="$missing uImage"
    [ -n "$DTB_SRC" ] || missing="$missing DTB"
    [ -n "$BITSTREAM_SRC" ] || missing="$missing system.bit"
    if [ -n "$missing" ]; then
        echo "ERROR: missing required S19j Pro am2 Zynq boot artifact(s):$missing" >&2
        echo "       Pass the exact output of stage_am2_sd_artifacts.sh; raw" >&2
        echo "       filename-only artifact directories are not admitted." >&2
        echo "       Use --allow-incomplete only for a known-nonbootable lab staging image." >&2
        exit 1
    fi
    ensure_python
    need_tool sha256sum "install coreutils"
    if [ -n "$BITSTREAM_OVERRIDE" ]; then
        validate_artifact_stage_manifest "$ARTIFACT_DIR" "$BITSTREAM_SRC"
    else
        validate_artifact_stage_manifest "$ARTIFACT_DIR"
        EXPECTED_HELD_BITSTREAM_SHA256="f9317611efc031705af33d1b595db20c62802f7aa45a3afc64cedbb62527d005"
        observed_bitstream_sha=$(sha256sum "$BITSTREAM_SRC" | awk '{print $1}')
        if [ "$observed_bitstream_sha" != "$EXPECTED_HELD_BITSTREAM_SHA256" ]; then
            echo "ERROR: default AM2 bitstream does not match held .139 provenance" >&2
            exit 1
        fi
    fi
fi

if [ "$VALIDATE_INPUTS_ONLY" -eq 1 ]; then
    echo "AM2_S19JPRO_SD_INPUTS_READY board_target=am2-s19j media_target=am2-s19jpro-sd idle_first=true"
    sd_common::cleanup || true
    trap - EXIT INT TERM
    exit 0
fi

sd_common::need_tool sfdisk     "sudo apt install util-linux"
sd_common::need_tool mkfs.vfat  "sudo apt install dosfstools"
sd_common::need_tool mcopy      "sudo apt install mtools"
sd_common::need_tool mkfs.ext2  "sudo apt install e2fsprogs"
sd_common::need_tool dd         "(coreutils)"
sd_common::need_tool sha256sum  "(coreutils)"

IMG_FILE="$SD_OUTPUT_DIR/dcentos-am2-s19jpro.img"
# `create_blank_image` opens IMG_FILE with truncation. Refuse source aliases
# (including existing hard links and symlinked parent paths) before touching
# either the image or its manifest.
sd_common::refuse_unsafe_output_alias "$IMG_FILE" \
    "$ROOTFS_SQUASHFS" "$BOOT_BIN_SRC" "$UBOOT_SRC" "$UIMAGE_SRC" \
    "$DTB_SRC" "$BITSTREAM_SRC" "$XIL_CONFIG_SRC"
sd_common::refuse_unsafe_output_alias "$IMG_FILE.manifest.json" \
    "$IMG_FILE" "$ROOTFS_SQUASHFS" "$BOOT_BIN_SRC" "$UBOOT_SRC" \
    "$UIMAGE_SRC" "$DTB_SRC" "$BITSTREAM_SRC" "$XIL_CONFIG_SRC"
if [ -e "$IMG_FILE.sig" ] || [ -L "$IMG_FILE.sig" ]; then
    echo "ERROR: refusing to rewrite an AM2 image beside stale signature: $IMG_FILE.sig" >&2
    echo "       Remove the signature explicitly before rebuilding." >&2
    exit 1
fi
UENV_STAGED=0
P1_OFFSET_MB=1
P1_SIZE_MB=64
P2_OFFSET_MB=$((P1_OFFSET_MB + P1_SIZE_MB))
# p2 = RAW squashfs root. Size = squashfs rounded up to MiB + 2 MiB slack
# (squashfs mount ignores trailing zeros; slack only de-risks rounding).
P2_SIZE_MB=$(( (ROOTFS_BYTES + 1048575) / 1048576 + 2 ))
P3_OFFSET_MB=$((P2_OFFSET_MB + P2_SIZE_MB))
# p3 = small ext2 /data partition (XIL quiet config + handoff helpers +
# bitstream copy). 16 MiB is ample for TOMLs + scripts + a ~1-10 MB .bit.
P3_SIZE_MB=16

# Boot artifacts must fit inside the fixed 64 MiB FAT p1.
BOOT_BYTES=0
for f in "$BOOT_BIN_SRC" "$UBOOT_SRC" "$UIMAGE_SRC" "$DTB_SRC" "$BITSTREAM_SRC"; do
    [ -n "$f" ] && [ -f "$f" ] && BOOT_BYTES=$((BOOT_BYTES + $(total_bytes "$f")))
done
if [ "$BOOT_BYTES" -gt $(( (P1_SIZE_MB - 4) * 1024 * 1024 )) ]; then
    echo "ERROR: boot artifacts ($BOOT_BYTES bytes) exceed the ${P1_SIZE_MB} MiB FAT boot partition" >&2
    exit 1
fi

NEEDED_MB=$((P3_OFFSET_MB + P3_SIZE_MB + 1))
if [ "$NEEDED_MB" -gt "$DISK_IMAGE_SIZE_MB" ]; then
    echo "[INFO] auto-growing disk image to ${NEEDED_MB} MB to fit payload"
    DISK_IMAGE_SIZE_MB="$NEEDED_MB"
fi

echo "=== am2-s19jpro SD disk image ==="
echo "Image:      $IMG_FILE"
echo "Size:       ${DISK_IMAGE_SIZE_MB} MB"
echo "Rootfs:     $ROOTFS_SQUASHFS ($((ROOTFS_BYTES/1024/1024)) MB)"
echo "Artifacts:  ${ARTIFACT_DIR:-none}"
echo "BOOT.bin:   ${BOOT_BIN_SRC:-missing}"
echo "uImage:     ${UIMAGE_SRC:-missing}"
echo "DTB:        ${DTB_SRC:-missing}"
echo "Bitstream:  ${BITSTREAM_SRC:-missing}"
echo "XIL config: ${XIL_CONFIG_SRC:-missing}"
echo ""

sd_common::create_blank_image "$IMG_FILE" "$DISK_IMAGE_SIZE_MB"

# MBR partition table:
#   p1: 1 MiB offset, 64 MiB FAT16 LBA (0x0e), bootable — FSBL + BOOT.bin
#       + kernel + DTB + bitstream + uEnv.txt.
#   p2: RAW squashfs (0x83) — the DCENT_OS root filesystem itself. The
#       kernel mounts it read-only (rootfstype=squashfs ro). PROVEN model:
#       identical to how .25/.109 boot DCENT_OS from NAND.
#   p3: small ext2 (0x83) /data partition — XIL quiet config + handoff
#       helpers + bitstream copy. Mountable on /data (see README inside).
sd_common::write_mbr_three_part_mb "$IMG_FILE" \
    "$P1_OFFSET_MB" "$P1_SIZE_MB" "0e" \
    "$P2_OFFSET_MB" "$P2_SIZE_MB" "83" \
    "$P3_OFFSET_MB" "$P3_SIZE_MB" "83"

BOOT_PART_TMP="$(mktemp)"
DATA_PART_TMP="$(mktemp)"
CLEANUP_PATHS+=("$BOOT_PART_TMP" "$DATA_PART_TMP")
# bs=1M boundary aligns with the MiB offsets above; equivalent to extracting
# `P1_OFFSET_MB * 2048` sectors but kept as the bs=1M form for parity with
# the pre-refactor builder.
dd if="$IMG_FILE" of="$BOOT_PART_TMP" bs=1M skip="$P1_OFFSET_MB" count="$P1_SIZE_MB" status=none
dd if="$IMG_FILE" of="$DATA_PART_TMP" bs=1M skip="$P3_OFFSET_MB" count="$P3_SIZE_MB" status=none

sd_common::format_fat16_partition "$BOOT_PART_TMP" "DCENTBOOT"

# --- p2: RAW squashfs root (the fix) ---
# Magic-verified + bounds-checked; written straight into the image. NEVER
# wrap it in an ext2 as a file — that was the "No init found" boot-loop
# defect (kernel mounts the ext2, finds no /sbin/init, panics).
sd_common::write_squashfs_root_partition "$IMG_FILE" "$ROOTFS_SQUASHFS" "$P2_OFFSET_MB" "$P2_SIZE_MB"

# --- p3: ext2 /data partition (XIL quiet config + helpers) ---
# The squashfs root is read-only, so the XIL config can't live inside it
# on this builder (we don't rebuild the squashfs). It rides on p3 instead:
#   /dcentrald.toml             — staged copy of the XIL quiet config at the
#       exact name S82dcentrald prefers when p3 is mounted on /data
#       (S82dcentrald: CONFIG="/data/dcentrald.toml" when present).
#   /dcentos/…                  — same content under a labelled dir + helpers.
# Runtime delivery: dcentos-early-init.sh tries `mount -t ubifs
# ubi0:rootfs_data /data` which FAILS gracefully on SD (no ubi0) and boot
# continues on the tmpfs /etc overlay fallback — boot does NOT break. To
# activate the quiet config on an SD boot, mount p3 over /data
# (`mount -t ext2 /dev/mmcblk0p3 /data`) before S82dcentrald starts — either
# manually from the rescue shell, or via a future SD-aware early-init
# fallback (out of scope for this builder; tracked in the 2026-06-10 SD
# boot defect session docs).
DATA_STAGE="$(mktemp -d)"
CLEANUP_PATHS+=("$DATA_STAGE")
mkdir -p "$DATA_STAGE/dcentos"
if [ -n "$XIL_CONFIG_SRC" ] && [ -f "$XIL_CONFIG_SRC" ]; then
    cp "$XIL_CONFIG_SRC" "$DATA_STAGE/dcentrald.toml"
    cp "$XIL_CONFIG_SRC" "$DATA_STAGE/dcentos/dcentrald_s19jpro_xil.toml"
fi
# Stage the three home-quiet helpers — required for safe BraiinsOS-to-DCENT
# handoff per the XIL bring-up contract.
for helper in xil_fan_guard.sh xil_prepare_dcentos_quiet.sh xil_quiet_stop.sh; do
    if [ -f "$SCRIPT_DIR/$helper" ]; then
        cp "$SCRIPT_DIR/$helper" "$DATA_STAGE/dcentos/$helper"
        chmod +x "$DATA_STAGE/dcentos/$helper" 2>/dev/null || true
    fi
done
# Per docs/reviews findings: bitstream is load-bearing. Stage it on the
# /data partition too so dcentrald can find it at runtime regardless of how
# U-Boot loaded the boot partition.
if [ -n "$BITSTREAM_SRC" ] && [ -f "$BITSTREAM_SRC" ]; then
    cp "$BITSTREAM_SRC" "$DATA_STAGE/dcentos/fpga_bitstream.bit"
fi
cat > "$DATA_STAGE/dcentos/README.txt" <<EOF
DCENT_OS am2-s19jpro SD-card /data partition (p3, ext2)
Created: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Layout:
  p2 of this card is the RAW DCENT_OS root squashfs (mounted ro by the
  kernel: root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait).
  /dcentrald.toml              - XIL quiet config (psu_override + PWM cap);
                                 picked up by S82dcentrald automatically IF
                                 this partition is mounted on /data:
                                   mount -t ext2 /dev/mmcblk0p3 /data
  /dcentos/dcentrald_s19jpro_xil.toml - same config, labelled copy
  /dcentos/fpga_bitstream.bit  - BraiinsOS s9-io-am2 bitstream (proven)
  /dcentos/xil_*.sh            - quiet handoff helpers
Safety:
  - No NAND writes; SD-card-only boot.
  - Without the /data mount, boot still completes (early-init's ubifs /data
    mount fails gracefully; /etc overlay falls back to tmpfs) but dcentrald
    uses the baked /etc/dcentrald.toml defaults, NOT the XIL quiet config.
  - bitstream is the proven s9-io-am2 path (2026-05-15 milestone).
EOF
mkfs.ext2 -L "DCENTDATA" -d "$DATA_STAGE" "$DATA_PART_TMP" >/dev/null

export MTOOLS_SKIP_CHECK=1

# Thin shim — kept so existing inline call sites continue to work without
# churning every site. Equivalent to sd_common::copy_one_to_fat.
copy_in() { sd_common::copy_one_to_fat "$@"; }

# Boot partition: FSBL + U-Boot + bitstream + kernel + DTB + uEnv.txt.
# BOOT.bin MUST be first to satisfy the Zynq BootROM SD-boot contract
# (BootROM scans FAT16 root for BOOT.bin at offset 0).
copy_in "$BOOT_PART_TMP" "$BOOT_BIN_SRC" "BOOT.bin"
copy_in "$BOOT_PART_TMP" "$UBOOT_SRC" "u-boot.img"
copy_in "$BOOT_PART_TMP" "$UIMAGE_SRC" "uImage"
copy_in "$BOOT_PART_TMP" "$DTB_SRC" "devicetree.dtb"
copy_in "$BOOT_PART_TMP" "$BITSTREAM_SRC" "system.bit"
# Convenience copy of the XIL quiet config on the FAT boot partition so the
# operator can inspect/edit it from any PC. The runtime-preferred copy lives
# on p3 (ext2 /data) — see the p3 staging block above.
copy_in "$BOOT_PART_TMP" "$XIL_CONFIG_SRC" "dcentrald_s19jpro_xil.toml"

if [ -n "$ARTIFACT_DIR" ]; then
    UENV_TMP="$(mktemp)"
    CLEANUP_PATHS+=("$UENV_TMP")
    cat > "$UENV_TMP" <<'EOF'
# DCENT_OS am2-s19jpro SD-boot uEnv.txt
# Loaded by BraiinsOS U-Boot from FAT16 partition 1.
dcent_bootfile=uImage
dcent_fdtfile=devicetree.dtb
dcent_bitfile=system.bit
dcent_rootpart=2
kloadaddr=0x2080000
fdtaddr=0x2000000
bitaddr=0x100000
# Partition 2 IS the DCENT_OS root filesystem: a RAW squashfs, mounted
# read-only by the kernel (the proven .25/.109 NAND runtime model). No
# initramfs (`bootm kernel - fdt`); /sbin/init comes from the squashfs and
# dcentos-early-init.sh sets up the writable tmpfs/data areas.
# Plain bootargs= so BraiinsOS sdboot's `test -n ${bootargs}` is satisfied and
# the default root=/dev/ram0 is overridden even before sd_uenvcmd runs. The
# sd_uenvcmd path re-runs bootargs_dcent (identical value) right before bootm.
bootargs=console=ttyPS0,115200 earlyprintk root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait dcent.platform=zynq-bm3-am2 dcent.sd_lab=1
bootargs_dcent=setenv bootargs console=ttyPS0,115200 earlyprintk root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait dcent.platform=zynq-bm3-am2 dcent.sd_lab=1
loadbit_dcent=load mmc 0:1 ${bitaddr} ${dcent_bitfile}
fpgaload_dcent=fpga loadb 0 ${bitaddr} ${filesize}
loaduimage_dcent=load mmc 0:1 ${kloadaddr} ${dcent_bootfile}
loadfdt_dcent=load mmc 0:1 ${fdtaddr} ${dcent_fdtfile}
# CRITICAL: the hook MUST be sd_uenvcmd, NOT uenvcmd. The BraiinsOS am2 U-Boot
# `sdboot` command runs `uenv_load` (load+import this file) then
# `if test -n ${sd_uenvcmd}; then run sd_uenvcmd; fi` — it NEVER runs a key
# named `uenvcmd` (decoded from the donor u-boot.img default env AND the live
# .139 saved env). A key named `uenvcmd` is imported but never executed → the
# card drops to the U-Boot prompt / does nothing. See team-A-uboot-chain.md +
# team-E-dtb-data-adversarial.md (2026-06-10 SD boot defect session).
sd_uenvcmd=echo DCENT_OS am2-s19jpro SD boot; if run loadbit_dcent; then run fpgaload_dcent; fi; if run loaduimage_dcent loadfdt_dcent bootargs_dcent; then bootm ${kloadaddr} - ${fdtaddr}; else echo DCENT_OS SD load failed; fi
EOF
    copy_in "$BOOT_PART_TMP" "$UENV_TMP" "uEnv.txt"
    UENV_STAGED=1
fi

# README on boot partition.
README_TMP="$(mktemp)"
CLEANUP_PATHS+=("$README_TMP")
cat > "$README_TMP" <<EOF
DCENT_OS am2-s19jpro SD-card boot image
Created: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Layout:  p1 (this FAT): BOOT.bin + uImage + devicetree.dtb + system.bit
         + uEnv.txt + dcentrald_s19jpro_xil.toml (inspection copy)
         p2: RAW DCENT_OS root squashfs (kernel mounts it read-only:
         root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait)
         p3: ext2 /data (XIL quiet config + handoff helpers)
Safety:  no NAND writes; SD-card-only boot. Reboot without SD returns to
         the unit's previous firmware (BraiinsOS / stock XIL / etc.).
Bitstream: BraiinsOS s9-io-am2 (proven 2026-05-15 first-accepted-shares).
           NEVER substitute the stock XIL Anthill bitstream.
EOF
copy_in "$BOOT_PART_TMP" "$README_TMP" "README.txt"

# Write partitions back into the image. p2 (raw squashfs) was already
# written directly by sd_common::write_squashfs_root_partition above.
dd if="$BOOT_PART_TMP" of="$IMG_FILE" bs=1M seek="$P1_OFFSET_MB" conv=notrunc status=none
dd if="$DATA_PART_TMP" of="$IMG_FILE" bs=1M seek="$P3_OFFSET_MB" conv=notrunc status=none
write_am2_sd_manifest

IMG_BYTES=$(total_bytes "$IMG_FILE")
echo ""
echo "=== Done ==="
echo "  Image: $IMG_FILE ($((IMG_BYTES / 1024 / 1024)) MB)"
echo "  Manifest: $IMG_FILE.manifest.json"
echo "  Flash: dd if=\"$IMG_FILE\" of=/dev/sdX bs=4M status=progress"
echo "         (or balenaEtcher / Rufus)"
echo ""
echo "  Operator pre-flight (per DevOps Q1 report A.5):"
echo "    1. Verify SD-jumper / SYSBOOT pins on the target am2 board."
echo "    2. From a running BraiinsOS unit: fw_setenv sd_boot yes"
echo "    3. Power-cycle into the SD."

if [ "$ALLOW_INCOMPLETE" -eq 1 ]; then
    echo ""
    echo "[WARN] --allow-incomplete was set. This image may not boot until"
    echo "       verified am2 Zynq boot artifacts are added."
fi
