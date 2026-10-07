#!/bin/sh
#
# DCENTos post-image script - exact S19k Pro Amlogic A113D package builder.
#
# Desk analog of the A126/Plus120 builder (am3-bm1362-nopic). Produces the
# exact model-named archive; the normal authenticated release gate remains
# active and the expected terminal state of a  build is its
# unsigned-package refusal, which retains the compiled userspace.
#

set -e

BINARIES_DIR="${BINARIES_DIR:-${BASE_DIR}/images}"
BOARD_NAME=$(sed -n 's/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}' \
    "${TARGET_DIR}/etc/dcentos/board_target" 2>/dev/null || true)
case "$BOARD_NAME" in
    am3-s19kpro) PRODUCT_LABEL="S19K Pro" ;;
    *) echo "ERROR: exact S19k Pro post-image target required" >&2; exit 1 ;;
esac
# A rootfs archive is not proof of its persistent writer or boot selector.
PACKAGE_INSTALL_AUTHORIZED=0
PACKAGE_STORAGE_AUTHORIZED=0
PACKAGE_POSTURE="exact native runtime BETA image; separate persistent installer admission required"
INSTALL_DETAIL="No persistent install authority is created by this image. Exact storage writer, boot selection and recovery must be separately admitted."
METADATA_INSTALL_CONTRACT="local image preparation only; no persistent writer or recovery authority"
BOARD_FAMILY="am3"
OUTPUT_BASENAME="dcentos-sysupgrade-${BOARD_NAME}.tar"
OUTPUT_TAR="${BINARIES_DIR}/${OUTPUT_BASENAME}"

echo "=== DCENTos Post-Image Builder (${BOARD_NAME}) ==="
echo ""

ROOTFS_CPIO="${BINARIES_DIR}/rootfs.cpio.gz"
if [ ! -f "$ROOTFS_CPIO" ]; then
    echo "ERROR: rootfs.cpio.gz not found in ${BINARIES_DIR}" >&2
    echo "  Enable BR2_TARGET_ROOTFS_CPIO=y + BR2_TARGET_ROOTFS_CPIO_GZIP=y" >&2
    echo "  in the ${BOARD_NAME} defconfig." >&2
    exit 1
fi

CPIO_SIZE=$(stat -c%s "$ROOTFS_CPIO")
echo "Rootfs:  rootfs.cpio.gz ($((CPIO_SIZE / 1024)) KB)"

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

require_rootfs_path "etc/dcentos-early-init.sh"
require_rootfs_path "etc/init.d/S45persistent"
require_rootfs_path "usr/libexec/dcentos/s19kpro-nopic-storage.py"
require_rootfs_path "etc/init.d/S50dropbear"
require_rootfs_path "etc/init.d/S70ip_reporter"
require_rootfs_path "etc/init.d/S80dashboard"
require_rootfs_path "etc/init.d/S81mcp"
require_rootfs_path "etc/init.d/S82dcentrald"
require_rootfs_path "usr/sbin/dropbear"
require_rootfs_path "usr/sbin/ubiattach"
require_rootfs_path "usr/local/bin/dcentrald"
require_rootfs_path "root/web/server.py"
require_rootfs_path "root/web/mcp_server.py"
require_rootfs_path "root/web/ip_reporter.py"
require_rootfs_path "uninstall.sh"
require_rootfs_path "etc/dcentos-platform"
require_rootfs_path "etc/fw_env.config"
reject_rootfs_pattern '(^|/)(S50telnet|in\.telnetd|telnetd|telnet)$|telnet'
reject_rootfs_pattern 'classic-aml-storage\.py|bm1362-nopic-storage\.py'
echo "Rootfs audit: access services present; telnet paths absent"

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
    -n "DCENT_OS ${PRODUCT_LABEL} rootfs" \
    -d "$ROOTFS_CPIO" \
    "$ROOTFS_UIMAGE"

ROOTFS_SIZE=$(stat -c%s "$ROOTFS_UIMAGE")
ROOTFS_SHA256=$(sha256sum "$ROOTFS_UIMAGE" | awk '{print $1}')
echo "uImage:  uImage_rootfs.bin ($((ROOTFS_SIZE / 1024)) KB)"
echo "  SHA256: ${ROOTFS_SHA256}"

PROJECT_ROOT="$(cd "${BR2_EXTERNAL_DCENTOS_PATH}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_package_common.sh"

if [ "$PACKAGE_STORAGE_AUTHORIZED" = "1" ]; then
    . "${PROJECT_ROOT}/scripts/lib/am3_geometry.sh"
    PACKAGE_ROOTFS_MAX_BYTES=$DCENT_AM3_ROOTFS_WINDOW_DEC
    PACKAGE_SIZE_LABEL="Amlogic rootfs window"
else
    # Build-resource ceiling only. This is not an admitted MTD window, offset,
    # write geometry, boot selector, rollback path, or recovery contract.
    PACKAGE_ROOTFS_MAX_BYTES=41943040
    PACKAGE_SIZE_LABEL="package-format rootfs ceiling"
fi

case "$ROOTFS_SIZE" in
    ''|*[!0-9]*)
        echo "ERROR: rootfs uImage size is not numeric: $ROOTFS_SIZE" >&2
        exit 1
        ;;
esac
if [ "$ROOTFS_SIZE" -gt "$PACKAGE_ROOTFS_MAX_BYTES" ]; then
    echo "ERROR: rootfs uImage exceeds ${PACKAGE_SIZE_LABEL}: ${ROOTFS_SIZE} > ${PACKAGE_ROOTFS_MAX_BYTES}" >&2
    exit 1
fi
echo "${PACKAGE_SIZE_LABEL}: ${ROOTFS_SIZE} <= ${PACKAGE_ROOTFS_MAX_BYTES} bytes"

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
        "${PROJECT_ROOT}/br2_external_dcentos/board/amlogic/${BOARD_NAME}/rootfs-overlay/etc/dcentos-version" \
        "${PROJECT_ROOT}/br2_external_dcentos/board/amlogic/am3-s19kpro-nopic/rootfs-overlay/etc/dcentos-version" \
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

# The helper binds TARGET to this model's exact fw-info (vnish 1.2.7 s19kpro
# donor identity; sibling-model and live repository fallbacks are forbidden).
. "${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/require-exact-build-inputs.sh"
dcent_require_exact_amlogic_build_inputs "${TARGET:-}"
KERNEL="$DCENT_AM3_AML_KERNEL"
KERNEL_SRC="exact model-bound build-input snapshot (${PRODUCT_LABEL}/aml)"

cp "$KERNEL" "${BINARIES_DIR}/kernel"
KERNEL_SIZE=$(stat -c%s "${BINARIES_DIR}/kernel")
KERNEL_SHA256=$(sha256sum "${BINARIES_DIR}/kernel" | awk '{print $1}')
echo "Kernel:  kernel ($((KERNEL_SIZE / 1024)) KB) from ${KERNEL_SRC}"
echo "  SHA256: ${KERNEL_SHA256}"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
SUP_DIR="$STAGING/sysupgrade-${BOARD_NAME}"
mkdir -p "$SUP_DIR"

cp "${BINARIES_DIR}/kernel" "$SUP_DIR/kernel"
cp "$ROOTFS_UIMAGE" "$SUP_DIR/root"

cat > "$SUP_DIR/METADATA" << EOF
DCENT_OS
D-Central Technologies
Build: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board: ${BOARD_NAME}
Kernel: Amlogic 4.9.113 (shared A113D runtime / ${PRODUCT_LABEL})
Rootfs: DCENTos (Buildroot, uImage-wrapped gzip CPIO)
Install contract: ${METADATA_INSTALL_CONTRACT}
EOF
METADATA_SHA256=$(sha256sum "$SUP_DIR/METADATA" | awk '{print $1}')
METADATA_SIZE=$(stat -c%s "$SUP_DIR/METADATA")

{
    echo "${KERNEL_SHA256}  kernel"
    echo "${ROOTFS_SHA256}  root"
    echo "${METADATA_SHA256}  METADATA"
} > "$SUP_DIR/SHA256SUMS"

cat > "$SUP_DIR/MANIFEST.json" << EOF
{
  "schema": 1,
  "product": "DCENT_OS",
  "family": "antminer",
  "package_type": "sysupgrade",
  "board_family": "${BOARD_FAMILY}",
  "board": "${BOARD_NAME}",
  "board_target": "${BOARD_NAME}",
  "version": "${PACKAGE_VERSION}",
  "created_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "payloads": {
    "kernel": {
      "path": "sysupgrade-${BOARD_NAME}/kernel",
      "size": ${KERNEL_SIZE},
      "sha256": "${KERNEL_SHA256}"
    },
    "rootfs": {
      "path": "sysupgrade-${BOARD_NAME}/root",
      "size": ${ROOTFS_SIZE},
      "sha256": "${ROOTFS_SHA256}"
    },
    "metadata": {
      "path": "sysupgrade-${BOARD_NAME}/METADATA",
      "sha256": "${METADATA_SHA256}"
    }
  },
  "toolbox": {
    "install_command": null,
    "update_command": null,
    "upload_endpoint": null,
    "board_target_header": null,
    "requires_inactive_slot": false
  }
}
EOF

# Final manifest/signature rewrite through the shared AM2/AM3 helper. Admitted
# targets expose guarded host-driven rootfs-window tooling; package-only targets
# remain non-installable format/evidence artifacts with no writer metadata.
if [ "$PACKAGE_INSTALL_AUTHORIZED" = "1" ]; then
    DCENT_TOOLBOX_INSTALL_COMMAND="dcent install <ip> -f ${OUTPUT_BASENAME} --artifact-dir <restore_verified_dir>"
    DCENT_TOOLBOX_INSTALL_MODE=host_driven_rootfs_window_lab
    DCENT_PACKAGE_STATUS=host_driven_only
    DCENT_PACKAGE_INSTALLABLE=true
else
    DCENT_TOOLBOX_INSTALL_COMMAND=""
    DCENT_TOOLBOX_INSTALL_MODE=package_only_denied
    DCENT_PACKAGE_STATUS=unvalidated_package_only
    DCENT_PACKAGE_INSTALLABLE=false
fi
if [ "$PACKAGE_INSTALL_AUTHORIZED" = "1" ]; then
    DCENT_TOOLBOX_UPDATE_COMMAND="dcent ota update-fleet <ip> -f ${OUTPUT_BASENAME} --artifact-dir <restore_verified_dir>"
else
    DCENT_TOOLBOX_UPDATE_COMMAND=""
fi
DCENT_TOOLBOX_REQUIRES_INACTIVE_SLOT=false
DCENT_TARGET_SIDE_SYSUPGRADE=false
dcent_stage_release_key
dcent_write_sysupgrade_manifest
dcent_sign_sysupgrade_manifest

(cd "$STAGING" && tar cf "$OUTPUT_TAR" "sysupgrade-${BOARD_NAME}/")
OUTPUT_SIZE=$(stat -c%s "$OUTPUT_TAR")
OUTPUT_SHA256=$(sha256sum "$OUTPUT_TAR" | awk '{print $1}')

echo ""
echo "Sysupgrade tarball:"
echo "  Path:   ${OUTPUT_TAR}"
echo "  Size:   $((OUTPUT_SIZE / 1024)) KB"
echo "  SHA256: ${OUTPUT_SHA256}"
echo ""
tar tf "$OUTPUT_TAR" | sed 's/^/  /'

cat > "${BINARIES_DIR}/BUILD_INFO.txt" << EOF
=== DCENTos ${BOARD_NAME} Build Info ===
Build date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board:      ${BOARD_NAME} (${PRODUCT_LABEL} Amlogic A113D NoPic; ${PACKAGE_POSTURE})
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

Install contract:
  ${METADATA_INSTALL_CONTRACT}
  ${INSTALL_DETAIL}
EOF
if [ "$PACKAGE_STORAGE_AUTHORIZED" = "1" ]; then
    cat >> "${BINARIES_DIR}/BUILD_INFO.txt" << EOF
  mtd=${DCENT_AM3_ROOTFS_MTD}
  rootfs_offset=${DCENT_AM3_ROOTFS_OFFSET_HEX}
  rootfs_window=${DCENT_AM3_ROOTFS_WINDOW_HEX}
EOF
else
    cat >> "${BINARIES_DIR}/BUILD_INFO.txt" << EOF
  No MTD number, offset, writable window, boot selector, rollback, or recovery
  geometry is claimed by this package.
EOF
fi
cat >> "${BINARIES_DIR}/BUILD_INFO.txt" << EOF

Target fleet:
  Exact held A113D vendor runtime identity for ${PRODUCT_LABEL} NoPic (BHB5690x); ${PACKAGE_POSTURE}
EOF

echo ""
echo "=== Build Complete (${BOARD_NAME}) ==="
