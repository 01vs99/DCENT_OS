#!/bin/sh
#
# DCENTos post-image script — am3-s19kpro (S19K Pro Amlogic NoPic variant)
# D-Central Technologies, 2026
#
# Produces a sysupgrade-shaped tarball with the "sysupgrade-am3-s19k/" prefix
# for signed host-driven rootfs-window installation. The rootfs is
# wrapped as a uImage and staged as `root` next to a verified `kernel`.
#
# Output files produced in $BINARIES_DIR:
#   - rootfs.cpio.gz                       (from Buildroot)
#   - uImage_rootfs.bin                    (mkimage-wrapped, our payload)
#   - kernel                               (staged from extractions)
#   - dcentos-sysupgrade-am3-s19kpro.tar (signed release)
#   - BUILD_INFO.txt
#
# The shared release signer signs the exact manifest in this build with a
# supplied private key and independent pinned public key. No custody receipt
# or later signing phase is required to assemble the artifact.
#
# CRITICAL — :
#   BOARD_NAME must be "am3-s19k" (not "am3-s19kpro" and not "am3-aml-s19k").
#   Wrong name = brick on flash. The directory inside the tar MUST be
#   `sysupgrade-am3-s19k/`.
#
set -e

BOARD_DIR="$(dirname "$0")"
BINARIES_DIR="${BINARIES_DIR:-${BASE_DIR}/images}"
PACKAGED_ELF_CHECK="${BOARD_DIR}/verify_rootfs_cpio_elf.py"

BOARD_NAME="am3-s19k"
BOARD_FAMILY="am3"
OUTPUT_TAR="${BINARIES_DIR}/dcentos-sysupgrade-am3-s19kpro.tar"

# A persistent-image build is release-only and reproducible. Building it
# does not execute the installer's backup, write or readback operations.
PROJECT_ROOT="$(cd "${BR2_EXTERNAL_DCENTOS_PATH}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_package_common.sh"
. "${PROJECT_ROOT}/scripts/lib/am3_geometry.sh"

# The physical mtd5 base is 0x06700000, including the 6 MiB hole before
# mtd1. U-Boot's 0x0B800000 rootfs therefore starts at mtd5+0x05100000.
# A caller cannot enlarge the 40 MiB window or substitute the size-sum base.
[ "$DCENT_AM3_ROOTFS_MTD" = /dev/mtd5 ] &&
[ "$DCENT_AM3_ROOTFS_OFFSET_HEX" = 0x05100000 ] &&
[ "$DCENT_AM3_ROOTFS_WINDOW_HEX" = 0x02800000 ] &&
[ "$DCENT_AM3_OFFSET_FROM_END_MTD0_TO_MTD1" = 0x600000 ] &&
[ "$DCENT_AM3_NANDROOTFS_GLOBAL" = 0x0B800000 ] || {
    echo "ERROR: S19k release requires its exact physical mtd5 rootfs geometry" >&2
    exit 1
}

[ "${DCENT_PACKAGE_STATUS:-release}" = release ] || {
    echo "ERROR: S19k persistent image requires DCENT_PACKAGE_STATUS=release" >&2
    exit 1
}
# RELEASE posture is required and — since WS-A4 (2026-09-01) — the default.
# An explicit DEV/LAB opt-out (DCENT_DEV_IMAGE=1 / DCENT_RELEASE_IMAGE=0)
# still fails closed here: the S19k persistent image is release-only.
dcent_release_posture_is_release || {
    echo "ERROR: S19k persistent image requires DCENT_RELEASE_IMAGE=1" >&2
    echo "       (the RELEASE image posture is the default; DCENT_DEV_IMAGE=1 /" >&2
    echo "        DCENT_RELEASE_IMAGE=0 selects a DEV/LAB image, which the S19k" >&2
    echo "        persistent lane refuses.)" >&2
    exit 1
}
[ "${DCENT_REQUIRE_RELEASE_KEY:-0}" = 1 ] || {
    echo "ERROR: S19k persistent image requires DCENT_REQUIRE_RELEASE_KEY=1" >&2
    exit 1
}
[ "${DCENT_S19K_UNSIGNED_INTERMEDIATE:-0}" = 0 ] || { echo "ERROR: S19k release requires the single signed posture; unsigned intermediates are not supported" >&2; exit 1; }
[ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ] || { echo "ERROR: S19k release requires DCENT_RELEASE_SIGNING_KEY" >&2; exit 1; }
[ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ] || { echo "ERROR: S19k persistent image requires DCENT_RELEASE_PUBKEY_FILE" >&2; exit 1; }
for required_file in "$DCENT_RELEASE_PUBKEY_FILE" "$DCENT_RELEASE_SIGNING_KEY"
do
    [ -f "$required_file" ] && [ ! -L "$required_file" ] || {
        echo "ERROR: required S19k release key is missing or unsafe: $required_file" >&2
        exit 1
    }
done
DCENT_PACKAGE_STATUS=release
export DCENT_PACKAGE_STATUS
dcent_release_provenance_init
[ "$DCENT_BUILD_TARGET" = dcentos_am3_s19kpro_defconfig ] || {
    echo "ERROR: release build target must be dcentos_am3_s19kpro_defconfig" >&2
    exit 1
}
case "$DCENT_BUILD_ARCH" in
    aarch64|aarch64-unknown-linux-musl) ;;
    *)
        echo "ERROR: release build architecture must be aarch64 (got: $DCENT_BUILD_ARCH)" >&2
        exit 1
        ;;
esac

echo "=== DCENTos Post-Image Builder (am3-s19kpro) ==="
echo ""

# -----------------------------------------------------------------------------
# Locate the rootfs.cpio.gz produced by Buildroot
# -----------------------------------------------------------------------------
ROOTFS_CPIO="${BINARIES_DIR}/rootfs.cpio.gz"
if [ ! -f "$ROOTFS_CPIO" ]; then
    echo "ERROR: rootfs.cpio.gz not found in ${BINARIES_DIR}" >&2
    echo "  Enable BR2_TARGET_ROOTFS_CPIO=y + BR2_TARGET_ROOTFS_CPIO_GZIP=y" >&2
    echo "  in the am3-s19kpro defconfig." >&2
    exit 1
fi

[ -f "$PACKAGED_ELF_CHECK" ] && [ ! -L "$PACKAGED_ELF_CHECK" ] || {
    echo "ERROR: packaged AArch64 ELF checker is missing or unsafe: $PACKAGED_ELF_CHECK" >&2
    exit 1
}

CPIO_SIZE=$(stat -c%s "$ROOTFS_CPIO")
echo "Rootfs:  rootfs.cpio.gz ($((CPIO_SIZE / 1024)) KB)"

# -----------------------------------------------------------------------------
# Rootfs service-surface audit.
#
# This package is meant to keep SSH/MCP/dashboard/IP Reporter/dcentrald access
# and must never expose BusyBox telnet again. Audit the cpio file list directly
# before wrapping it into a uImage so the build fails before producing a tarball.
# -----------------------------------------------------------------------------
ROOTFS_LIST="${BINARIES_DIR}/ROOTFS_FILELIST.txt"
ROOTFS_AUDIT_HITS="${BINARIES_DIR}/ROOTFS_AUDIT_HITS.txt"

if ! gzip -dc "$ROOTFS_CPIO" | cpio -it --quiet | sed 's#^\./##' | sort -u > "$ROOTFS_LIST"; then
    echo "ERROR: failed to list rootfs.cpio.gz for service-surface audit" >&2
    exit 1
fi

require_rootfs_path() {
    if ! grep -qx "$1" "$ROOTFS_LIST"; then
        echo "ERROR: rootfs service-surface audit missing required path: $1" >&2
        exit 1
    fi
}

reject_rootfs_pattern() {
    if grep -Ei "$1" "$ROOTFS_LIST" > "$ROOTFS_AUDIT_HITS"; then
        echo "ERROR: rootfs service-surface audit rejected path(s):" >&2
        sed 's/^/  /' "$ROOTFS_AUDIT_HITS" >&2
        exit 1
    fi
}

require_rootfs_path "etc/init.d/S38s19k-data"
require_rootfs_path "etc/init.d/S49s19k-postinstall-witness"
require_rootfs_path "etc/init.d/S50dropbear"
require_rootfs_path "etc/init.d/S70ip_reporter"
require_rootfs_path "etc/init.d/S80dashboard"
require_rootfs_path "etc/init.d/S81mcp"
require_rootfs_path "etc/init.d/S82dcentrald"
require_rootfs_path "usr/sbin/dropbear"
require_rootfs_path "usr/sbin/ubiattach"
require_rootfs_path "usr/bin/dropbearkey"
require_rootfs_path "usr/bin/openssl"
require_rootfs_path "usr/bin/python3"
reject_rootfs_pattern '(^|/)dcent-s19k-postinstall-witness.py$'
require_rootfs_path "usr/sbin/dcent-s19k-data-mount"
require_rootfs_path "usr/local/bin/dcentrald"
require_rootfs_path "usr/share/dcentos/install-custody/dcentrald_s19k.toml"
require_rootfs_path "root/web/server.py"
require_rootfs_path "root/web/mcp_server.py"
require_rootfs_path "root/web/ip_reporter.py"
require_rootfs_path "uninstall.sh"
require_rootfs_path "etc/dcentos-platform"
require_rootfs_path "etc/fw_env.config"
reject_rootfs_pattern '(^|/)(S50telnet|in\.telnetd|telnetd|telnet)$|telnet'
reject_rootfs_pattern '(^|/)S46post-install$'
echo "Rootfs audit: persistent operator access services present; historical witness, unsigned S46 and telnet paths absent"

# Re-admit the executable bytes from the final compressed cpio, not merely the
# target tree post-build inspected. This closes the post-build -> filesystem
# image boundary and rejects duplicate/symlink/traversal aliases for the daemon.
python3 "$PACKAGED_ELF_CHECK" \
    "$ROOTFS_CPIO" \
    "usr/local/bin/dcentrald" \
    "packaged /usr/local/bin/dcentrald"

# post-build installs the optional Rust dcentos-init as a regular /sbin/init;
# the BusyBox fallback remains a symlink. If the selected target tree contains
# the regular custom init, re-admit those final cpio bytes too so a late image
# mutation cannot bypass the source/staged checks.
if [ -n "${TARGET_DIR:-}" ] && [ -f "${TARGET_DIR}/sbin/init" ] && [ ! -L "${TARGET_DIR}/sbin/init" ]; then
    python3 "$PACKAGED_ELF_CHECK" \
        "$ROOTFS_CPIO" \
        "sbin/init" \
        "packaged optional /sbin/init"
fi

# -----------------------------------------------------------------------------
# Wrap rootfs.cpio.gz into a uImage. The Amlogic boot chain (BL2 -> FIP ->
# U-Boot 2015.01) loads the rootfs as a ramdisk uImage from mtd5.
#
# arm64 ramdisk image, gzip compressed payload.
# -----------------------------------------------------------------------------
HOST_MKIMAGE="${HOST_DIR}/bin/mkimage"
if [ ! -x "$HOST_MKIMAGE" ]; then
    HOST_MKIMAGE="$(command -v mkimage 2>/dev/null || true)"
fi
if [ -z "$HOST_MKIMAGE" ] || [ ! -x "$HOST_MKIMAGE" ]; then
    echo "ERROR: mkimage not found in HOST_DIR/bin or PATH" >&2
    echo "  Enable BR2_PACKAGE_HOST_UBOOT_TOOLS=y in the defconfig." >&2
    exit 1
fi

ROOTFS_UIMAGE="${BINARIES_DIR}/uImage_rootfs.bin"
"$HOST_MKIMAGE" \
    -A arm64 \
    -O linux \
    -T ramdisk \
    -C gzip \
    -n "DCENT_OS S19K Pro rootfs" \
    -d "$ROOTFS_CPIO" \
    "$ROOTFS_UIMAGE"

ROOTFS_SIZE=$(stat -c%s "$ROOTFS_UIMAGE")
ROOTFS_SHA256=$(sha256sum "$ROOTFS_UIMAGE" | awk '{print $1}')
echo "uImage:  uImage_rootfs.bin ($((ROOTFS_SIZE / 1024)) KB)"
echo "  SHA256: ${ROOTFS_SHA256}"

# The kernel is admitted below with the exact target's manifest-pinned DTB and
# fw-info identity. Sibling-model and live repository fallbacks are forbidden.
# BR2_EXTERNAL_DCENTOS_PATH = DCENT_OS_Antminer/br2_external_dcentos;
# PROJECT_ROOT and exact release provenance were sealed before mkimage.

case "$ROOTFS_SIZE" in
    ''|*[!0-9]*)
        echo "ERROR: rootfs uImage size is not numeric: $ROOTFS_SIZE" >&2
        exit 1
        ;;
esac
if [ "$ROOTFS_SIZE" -gt "$DCENT_AM3_ROOTFS_WINDOW_DEC" ]; then
    echo "ERROR: rootfs uImage exceeds Amlogic rootfs window: ${ROOTFS_SIZE} > ${DCENT_AM3_ROOTFS_WINDOW_DEC}" >&2
    exit 1
fi
echo "Rootfs window: ${ROOTFS_SIZE} <= ${DCENT_AM3_ROOTFS_WINDOW_DEC} bytes"

read_first_nonempty_line() {
    sed -n 's/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}' "$1"
}

infer_package_version() {
    if [ -n "${DCENT_PACKAGE_VERSION:-}" ]; then
        printf '%s\n' "${DCENT_PACKAGE_VERSION}"
        return 0
    fi

    for candidate in \
        "${TARGET_DIR:-}/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
    do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            value=$(read_first_nonempty_line "$candidate")
            if [ -n "$value" ]; then
                printf '%s\n' "$value"
                return 0
            fi
        fi
    done

    return 1
}

PACKAGE_VERSION=$(infer_package_version || true)
if [ -z "$PACKAGE_VERSION" ]; then
    echo "ERROR: unable to infer package version; set DCENT_PACKAGE_VERSION or ship /etc/dcentos-version" >&2
    exit 1
fi
case "$PACKAGE_VERSION" in
    *[!A-Za-z0-9._+:-]*)
        echo "ERROR: package version contains unsupported characters: $PACKAGE_VERSION" >&2
        exit 1
        ;;
esac
echo "Version: ${PACKAGE_VERSION}"

# Only the target-selected, manifest-pinned snapshot is admissible. The exact
# fw-info is part of the gate so shared kernel/DTB bytes cannot imply identity.
. "${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/require-exact-build-inputs.sh"
dcent_require_exact_amlogic_build_inputs "${TARGET:-}"
KERNEL="$DCENT_AM3_AML_KERNEL"
KERNEL_SRC="exact model-bound build-input snapshot (s19kpro/aml)"

cp "$KERNEL" "${BINARIES_DIR}/kernel"
KERNEL_SIZE=$(stat -c%s "${BINARIES_DIR}/kernel")
KERNEL_SHA256=$(sha256sum "${BINARIES_DIR}/kernel" | awk '{print $1}')
echo "Kernel:  kernel ($((KERNEL_SIZE / 1024)) KB) from ${KERNEL_SRC}"
echo "  SHA256: ${KERNEL_SHA256}"

# -----------------------------------------------------------------------------
# Stage sysupgrade-am3-s19k/ and build tarball
# -----------------------------------------------------------------------------
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
SUP_DIR="$STAGING/sysupgrade-${BOARD_NAME}"
mkdir -p "$SUP_DIR"

cp "${BINARIES_DIR}/kernel" "$SUP_DIR/kernel"
cp "$ROOTFS_UIMAGE"          "$SUP_DIR/root"

# METADATA file (OpenWrt convention)
cat > "$SUP_DIR/METADATA" << EOF
DCENT_OS
D-Central Technologies
Build: ${DCENT_CREATED_AT_UTC}
Board: ${BOARD_NAME}
Kernel: Amlogic 4.9.113 (am3-aml / S19K Pro NoPic)
Rootfs: DCENTos (Buildroot, uImage-wrapped gzip CPIO)
Artifact contract: signed host-driven rootfs-window image; target-side sysupgrade unsupported
EOF
METADATA_SHA256=$(sha256sum "$SUP_DIR/METADATA" | awk '{print $1}')
METADATA_SIZE=$(stat -c%s "$SUP_DIR/METADATA")

# Exact kernel/root bytes and the public trust root are covered by the shared
# manifest. Custody receipts and host-side recovery scripts are not runtime
# payloads and cannot be prerequisites for this signed build.
{
    echo "${KERNEL_SHA256}  kernel"
    echo "${ROOTFS_SHA256}  root"
    echo "${METADATA_SHA256}  METADATA"
} > "$SUP_DIR/SHA256SUMS"
DCENT_TOOLBOX_INSTALL_COMMAND="dcent install <ip> -f dcentos-sysupgrade-am3-s19kpro.tar --artifact-dir <restore_verified_dir>"
DCENT_TOOLBOX_UPDATE_COMMAND="$DCENT_TOOLBOX_INSTALL_COMMAND"
DCENT_TOOLBOX_REQUIRES_INACTIVE_SLOT=false
DCENT_TOOLBOX_INSTALL_MODE=host_driven_rootfs_window_lab
DCENT_TARGET_SIDE_SYSUPGRADE=false
DCENT_PACKAGE_INSTALLABLE=true
# Do not allow ambient metadata from another package to add unreviewed payloads.
DCENT_EXTRA_PAYLOAD_BLOCK=""
export DCENT_EXTRA_PAYLOAD_BLOCK
dcent_stage_release_key
dcent_write_sysupgrade_manifest
dcent_sign_sysupgrade_manifest

# Normalize signed package metadata for reproducible ordering and ownership.
find "$SUP_DIR" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
(cd "$STAGING" && tar --sort=name --format=ustar --owner=0 --group=0 \
    --numeric-owner --mtime="@${SOURCE_DATE_EPOCH}" \
    -cf "$OUTPUT_TAR" "sysupgrade-${BOARD_NAME}/")
OUTPUT_SIZE=$(stat -c%s "$OUTPUT_TAR")
OUTPUT_SHA256=$(sha256sum "$OUTPUT_TAR" | awk '{print $1}')

echo ""
echo "Sysupgrade tarball:"
echo "  Path:   ${OUTPUT_TAR}"
echo "  Size:   $((OUTPUT_SIZE / 1024)) KB"
echo "  SHA256: ${OUTPUT_SHA256}"
echo ""
tar tf "$OUTPUT_TAR" | sed 's/^/  /'

# -----------------------------------------------------------------------------
# Build info file
# -----------------------------------------------------------------------------
cat > "${BINARIES_DIR}/BUILD_INFO.txt" << EOF
=== DCENTos am3-s19kpro Build Info ===
Build date: ${DCENT_CREATED_AT_UTC}
Board:      ${BOARD_NAME} (S19K Pro Amlogic am3-aml NoPic variant)
Board family: ${BOARD_FAMILY}

Sysupgrade tarball:
  File:   $(basename "${OUTPUT_TAR}")
  Size:   ${OUTPUT_SIZE} bytes
  SHA256: ${OUTPUT_SHA256}

Kernel: ${KERNEL_SRC}
  Size:   ${KERNEL_SIZE} bytes
  SHA256: ${KERNEL_SHA256}

Rootfs (uImage-wrapped gzip CPIO): uImage_rootfs.bin
  Size:   ${ROOTFS_SIZE} bytes
  SHA256: ${ROOTFS_SHA256}

Artifact contract:
  Signed manifest with exact kernel/root payload hashes and a pinned public key.
  Host installation retains backup, exact geometry and write/readback checks.
  No NAND write occurred during package construction.
  The package is structurally installable for the host extractor, but it grants no writer:
  mutation authority stays with the reviewed host transaction, never this artifact.
  Offline package inspection:
    scripts/pre_flash_validate.sh --package-only $(basename "${OUTPUT_TAR}") ${BOARD_NAME}
  Recorded research geometry (not mutation authority):
    mtd=${DCENT_AM3_ROOTFS_MTD}
    rootfs_offset=${DCENT_AM3_ROOTFS_OFFSET_HEX}
    rootfs_window=${DCENT_AM3_ROOTFS_WINDOW_HEX}

Target fleet:
  am3-s19k (Amlogic S19k Pro, BM1366)
EOF

echo ""
echo "=== Build Complete (am3-s19kpro) ==="
