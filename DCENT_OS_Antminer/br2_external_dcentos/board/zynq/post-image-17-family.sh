#!/bin/sh
# Shared exact 17-family post-image. Current Beta producer composes native SD;
# the legacy package-only UBI branch retains its donor and geometry checks.
set -e

[ "${1:-}" = --board-target ] && [ "$#" -ge 2 ] || {
    echo "ERROR: shared 17-family post-image requires an exact target" >&2; exit 2;
}
BOARD_NAME=$2
shift 2
case "$BOARD_NAME" in am2-s17p|am2-s17plus|am2-t17|am2-t17plus) ;; *) exit 2 ;; esac
PROJECT_ROOT="$(cd "${BR2_EXTERNAL_DCENTOS_PATH}/.." && pwd)"
# Inside Buildroot make the host toolchain's minimal python3 shadows the
# container system python; release_native_sd.py needs the system python's
# site packages (python3-cryptography). Pin it for both invocations.
BUILD_TARGET=$(/usr/bin/python3 "$PROJECT_ROOT/scripts/release_producer.py" query "$BOARD_NAME" build_target)
if [ -n "${DCENT_NATIVE_SD_BOOT_INPUTS:-}" ]; then
    exec /usr/bin/python3 "$PROJECT_ROOT/scripts/release_native_sd.py" assemble \
        --rootfs "$TARGET_DIR" --images "${BINARIES_DIR:-${BASE_DIR}/images}" \
        --board-target "$BOARD_NAME" --boot-inputs "$DCENT_NATIVE_SD_BOOT_INPUTS"
fi
BOARD_DIR="${BR2_EXTERNAL_DCENTOS_PATH}/board/zynq/${BUILD_TARGET}"
BINARIES_DIR="${BINARIES_DIR:-${BASE_DIR}/images}"

BOARD_FAMILY="am2"
OUTPUT_TAR="${BINARIES_DIR}/dcentos-sysupgrade-${BUILD_TARGET}.tar"

echo "=== DCENTos Post-Image Builder (${BUILD_TARGET}) ==="
echo "    Exact S17 donor; model-bound UBI FIT; package-only/install-denied."
echo ""

# -----------------------------------------------------------------------------
# Locate the rootfs produced by Buildroot
# -----------------------------------------------------------------------------
ROOTFS="${BINARIES_DIR}/rootfs.squashfs"
if [ ! -f "$ROOTFS" ]; then
    echo "ERROR: rootfs.squashfs not found in ${BINARIES_DIR}" >&2
    echo "  Enable BR2_TARGET_ROOTFS_SQUASHFS=y in the ${BUILD_TARGET} defconfig." >&2
    exit 1
fi

ROOTFS_SIZE=$(stat -c%s "$ROOTFS")
ROOTFS_SHA256=$(sha256sum "$ROOTFS" | awk '{print $1}')
echo "Rootfs:  $(basename "$ROOTFS") ($((ROOTFS_SIZE / 1024)) KB)"
echo "  SHA256: ${ROOTFS_SHA256}"

# -----------------------------------------------------------------------------
# Admit only the exact held Braiins S17 SD image. Stock archives and arbitrary
# kernel/DTB overrides are deliberately not inputs: the stock uImage follows a
# different raw-MTD+ramdisk boot contract and is too large for the canonical
# UBI kernel volume. The donor helper proves the disk/FAT/U-Boot/source-FIT,
# extracts the exact S17 UBI kernel and model-bound DTB, and refuses all drift.
# -----------------------------------------------------------------------------
PROJECT_ROOT="$(cd "${BR2_EXTERNAL_DCENTOS_PATH}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_package_common.sh"
. "${PROJECT_ROOT}/scripts/lib/sysupgrade_archive_admission.sh"
ZYNQ_GEOMETRY_HELPER="${PROJECT_ROOT}/scripts/lib/sysupgrade_zynq_geometry.sh"
[ -r "$ZYNQ_GEOMETRY_HELPER" ] || {
    echo "ERROR: canonical Zynq geometry helper is missing: $ZYNQ_GEOMETRY_HELPER" >&2
    exit 1
}
# shellcheck source=/dev/null
. "$ZYNQ_GEOMETRY_HELPER"
dcent_zynq_geometry_require_payload_fit "$BOARD_NAME" rootfs "$ROOTFS_SIZE" || exit 1
echo "Geometry: $(dcent_zynq_geometry_receipt "$BOARD_NAME")"

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
        "${PROJECT_ROOT}/br2_external_dcentos/board/zynq/${BUILD_TARGET}/rootfs-overlay/etc/dcentos-version" \
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

KERNEL_ADMISSION_TOOL="${PROJECT_ROOT}/scripts/extract_am2_s17_kernel.py"
[ -r "$KERNEL_ADMISSION_TOOL" ] || {
    echo "ERROR: S17 kernel admission helper is missing: $KERNEL_ADMISSION_TOOL" >&2
    exit 1
}
if [ -z "${DCENT_AM2_S17_BRAIINS_SD_IMAGE:-}" ] || [ ! -f "${DCENT_AM2_S17_BRAIINS_SD_IMAGE}" ]; then
    echo "ERROR: exact held S17 donor is required; refusing package creation" >&2
    echo "  set DCENT_AM2_S17_BRAIINS_SD_IMAGE to braiins-os_am2-s17_sd.img" >&2
    exit 1
fi

if [ -n "${DCENT_AM2_S17_KERNEL:-}${DCENT_AM2_S17_DTB:-}${DCENT_AM2_S17_VENDOR_ARCHIVE:-}${DCENT_AM2_S17_CROSSCHECK_ARCHIVE:-}" ]; then
    echo "ERROR: stock archives and kernel/DTB overrides are not admitted by the S17 UBI FIT path" >&2
    exit 1
fi

MKIMAGE=""
if [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/mkimage" ]; then
    MKIMAGE="${HOST_DIR}/bin/mkimage"
else
    MKIMAGE=$(command -v mkimage || true)
fi
[ -n "$MKIMAGE" ] && [ -x "$MKIMAGE" ] || {
    echo "ERROR: host mkimage with FIT support is required" >&2
    exit 1
}

KERNEL_ADMISSION_DIR=$(mktemp -d)
cleanup_s17_admission() {
    rm -rf -- "$KERNEL_ADMISSION_DIR"
}
trap cleanup_s17_admission EXIT HUP INT TERM
/usr/bin/python3 "$KERNEL_ADMISSION_TOOL" extract \
    --donor "${DCENT_AM2_S17_BRAIINS_SD_IMAGE}" \
    --kernel-output "${KERNEL_ADMISSION_DIR}/kernel.bin" \
    --dtb-output "${KERNEL_ADMISSION_DIR}/s17.dtb" \
    --receipt "${KERNEL_ADMISSION_DIR}/donor-admission.json" >/dev/null || {
        echo "ERROR: S17 Braiins donor failed exact admission" >&2
        exit 1
    }

# The four exact AM2 17-series targets use the same pinned carrier kernel/DTB.
# Keep the canonical FIT bytes; target identity belongs to signed package metadata.
cat > "${KERNEL_ADMISSION_DIR}/s17-ubi-kernel.its" << 'EOF'
/dts-v1/;

/ {
    description = "DCENT_OS S17 model-bound UBI kernel FIT";
    #address-cells = <1>;

    images {
        kernel@1 {
            description = "DCENT_OS S17 UBI kernel";
            data = /incbin/("kernel.bin");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "none";
            load = <0x00008000>;
            entry = <0x00008000>;
            hash@1 { algo = "crc32"; };
            hash@2 { algo = "sha1"; };
        };

        fdt@1 {
            description = "Antminer S17 model-bound device tree";
            data = /incbin/("s17.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1 { algo = "crc32"; };
            hash@2 { algo = "sha1"; };
        };
    };

    configurations {
        default = "config@1";
        config@1 {
            description = "DCENT_OS S17 kernel plus exact S17 DTB";
            kernel = "kernel@1";
            fdt = "fdt@1";
        };
    };
};
EOF

# Bind generated FIT timestamps to the exact donor source FIT timestamp. This
# keeps the host artifact reproducible without changing release provenance.
S17_FIT_SOURCE_DATE_EPOCH=1740171698
(
    cd "$KERNEL_ADMISSION_DIR"
    SOURCE_DATE_EPOCH="$S17_FIT_SOURCE_DATE_EPOCH" "$MKIMAGE" \
        -f s17-ubi-kernel.its s17-ubi-kernel.itb >/dev/null
)
/usr/bin/python3 "$KERNEL_ADMISSION_TOOL" verify-fit \
    --fit "${KERNEL_ADMISSION_DIR}/s17-ubi-kernel.itb" \
    > "${KERNEL_ADMISSION_DIR}/fit-admission.json" || {
        echo "ERROR: rebuilt S17 UBI FIT failed exact model/geometry admission" >&2
        exit 1
    }

cp "${KERNEL_ADMISSION_DIR}/s17-ubi-kernel.itb" "${BINARIES_DIR}/kernel"
cp "${KERNEL_ADMISSION_DIR}/donor-admission.json" "${BINARIES_DIR}/am2-s17-donor-admission.json"
cp "${KERNEL_ADMISSION_DIR}/fit-admission.json" "${BINARIES_DIR}/am2-s17-fit-admission.json"
rm -rf -- "$KERNEL_ADMISSION_DIR"
KERNEL_ADMISSION_DIR=""
trap - EXIT HUP INT TERM
KERNEL_SRC="exact held Braiins AM2 S17 donor (model-bound kernel+DTB FIT)"
KERNEL_SIZE=$(stat -c%s "${BINARIES_DIR}/kernel")
KERNEL_SHA256=$(sha256sum "${BINARIES_DIR}/kernel" | awk '{print $1}')
dcent_zynq_geometry_require_payload_fit "$BOARD_NAME" kernel "$KERNEL_SIZE" || exit 1
echo "Kernel:  kernel ($((KERNEL_SIZE / 1024)) KB) from ${KERNEL_SRC}"
echo "  SHA256: ${KERNEL_SHA256}"

# -----------------------------------------------------------------------------
# Stage sysupgrade-am2-s17p/ and build tarball
# -----------------------------------------------------------------------------
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
SUP_DIR="$STAGING/sysupgrade-${BOARD_NAME}"
mkdir -p "$SUP_DIR"

cp "${BINARIES_DIR}/kernel" "$SUP_DIR/kernel"
cp "$ROOTFS"                "$SUP_DIR/root"

# METADATA file (OpenWrt convention)
cat > "$SUP_DIR/METADATA" << EOF
DCENT_OS
D-Central Technologies
Build: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board: ${BOARD_NAME}
Kernel: exact-donor Linux 4.4.0-xilinx + model-bound 17-family DTB FIT — EXPERIMENTAL
Rootfs: DCENTos (Buildroot)
EOF
METADATA_SHA256=$(sha256sum "$SUP_DIR/METADATA" | awk '{print $1}')
METADATA_SIZE=$(stat -c%s "$SUP_DIR/METADATA")

# SHA256SUMS
{
    echo "${KERNEL_SHA256}  kernel"
    echo "${ROOTFS_SHA256}  root"
    echo "${METADATA_SHA256}  METADATA"
} > "$SUP_DIR/SHA256SUMS"

# MANIFEST.json (matches package_sysupgrade.sh schema 1)
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
    "requires_inactive_slot": true
  }
}
EOF

# Final manifest/signature rewrite through the shared helper. This is a
# package-validation artifact only: no Toolbox install/update route is emitted.
DCENT_TOOLBOX_INSTALL_COMMAND=""
DCENT_TOOLBOX_UPDATE_COMMAND=""
DCENT_TOOLBOX_REQUIRES_INACTIVE_SLOT=true
DCENT_TOOLBOX_INSTALL_MODE=package_only_denied
DCENT_TARGET_SIDE_SYSUPGRADE=true
DCENT_PACKAGE_INSTALLABLE=false
DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-unvalidated_target_sysupgrade}"
. "$PROJECT_ROOT/scripts/lib/am2_native_ota_payload.sh"
dcent_stage_am2_native_ota_payload || exit 1

dcent_stage_release_key
dcent_write_sysupgrade_manifest
dcent_sign_sysupgrade_manifest

# Build tarball
(cd "$STAGING" && tar cf "$OUTPUT_TAR" "sysupgrade-${BOARD_NAME}/")
dcent_sysupgrade_archive_admit "$OUTPUT_TAR" "$BOARD_NAME" "$STAGING" || {
    echo "ERROR: generated sysupgrade archive failed canonical admission" >&2
    exit 1
}
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
=== DCENTos ${BUILD_TARGET} Build Info (EXPERIMENTAL package) ===
Build date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Board:      ${BOARD_NAME} (exact Zynq AM2 17-series variant)
Board family: ${BOARD_FAMILY}
Status:     Exact 17-family UBI boot donor admitted via ${KERNEL_SRC}.
            Package-only artifact: stock first-install and all Toolbox install/
            update routing remain denied.
            No live S17 / S17 Pro cold-boot, rollback, thermal, or accepted-
            share proof exists. Persistent use remains explicit lab-only.

Sysupgrade tarball:
  File:   $(basename "${OUTPUT_TAR}")
  Size:   ${OUTPUT_SIZE} bytes
  SHA256: ${OUTPUT_SHA256}

Kernel: ${KERNEL_SRC}
  Size:   ${KERNEL_SIZE} bytes
  SHA256: ${KERNEL_SHA256}

Rootfs: rootfs.squashfs
  Size:   ${ROOTFS_SIZE} bytes
  SHA256: ${ROOTFS_SHA256}

Target fleet:
  (none — no live T17 unit)
EOF

echo ""
echo "=== Build Complete (${BUILD_TARGET} — EXPERIMENTAL package, no live proof) ==="
