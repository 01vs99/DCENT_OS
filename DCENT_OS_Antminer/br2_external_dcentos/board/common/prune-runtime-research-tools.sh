#!/bin/sh
# Remove standalone hardware and boot-state research executors from normal
# runtime images.
#
# These sources remain in the repository for offline protocol research, but
# they open I2C/UART/UIO/devmem independently and therefore cannot coexist with
# dcentrald's exclusive hardware ownership. A future repair image may install
# them behind an explicit maintenance-mode lease. Until then, every product
# applies this post-build step after all packages and rootfs overlays so a
# shared Zynq overlay or package cannot accidentally reintroduce them.

set -eu

# Canonical image-posture resolution (WS-A4, 2026-09-01): RELEASE is the
# default; DCENT_DEV_IMAGE=1 (or an explicit DCENT_RELEASE_IMAGE=0) is the
# DEV/LAB opt-out. Resolve the shared helper from the checkout layout.
if ! command -v dcent_release_posture_is_release >/dev/null 2>&1; then
    _dcent_posture_lib=""
    if [ -n "${BR2_EXTERNAL_DCENTOS_PATH:-}" ] &&
        [ -f "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_posture.sh" ]; then
        _dcent_posture_lib="${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_posture.sh"
    elif [ -n "${PROJECT_ROOT:-}" ] &&
        [ -f "${PROJECT_ROOT}/scripts/lib/release_posture.sh" ]; then
        _dcent_posture_lib="${PROJECT_ROOT}/scripts/lib/release_posture.sh"
    else
        _dcent_prune_self_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
        if [ -f "${_dcent_prune_self_dir}/../../../scripts/lib/release_posture.sh" ]; then
            _dcent_posture_lib="${_dcent_prune_self_dir}/../../../scripts/lib/release_posture.sh"
        fi
    fi
    [ -n "$_dcent_posture_lib" ] || {
        echo "prune-runtime-research-tools: cannot locate scripts/lib/release_posture.sh" >&2
        exit 1
    }
    . "$_dcent_posture_lib"
    unset _dcent_posture_lib _dcent_prune_self_dir
fi

TARGET_DIR=${1:?Buildroot TARGET_DIR argument is required}
if [ ! -d "$TARGET_DIR" ]; then
    echo "refusing non-directory TARGET_DIR: '$TARGET_DIR'" >&2
    exit 1
fi
TARGET_DIR=$(CDPATH= cd "$TARGET_DIR" && pwd -P)
case "$TARGET_DIR" in
    /|"")
        echo "refusing unsafe TARGET_DIR: '$TARGET_DIR'" >&2
        exit 1
        ;;
esac
if [ ! -d "$TARGET_DIR/etc" ] || [ ! -d "$TARGET_DIR/bin" ]; then
    echo "refusing TARGET_DIR without Buildroot rootfs sentinels: '$TARGET_DIR'" >&2
    exit 1
fi

# Never traverse an intermediate symlink while deleting. A malformed staging
# tree with root -> /somewhere or usr -> /somewhere could otherwise turn a
# bounded prune into a host-filesystem mutation outside TARGET_DIR.
for component in root usr usr/bin usr/sbin; do
    if [ -L "$TARGET_DIR/$component" ]; then
        echo "refusing TARGET_DIR with symlinked delete-path component: '$component'" >&2
        exit 1
    fi
done

# The whole directory is a research-only namespace. Removing the namespace,
# rather than a filename allowlist, also excludes ignored bytecode, editor
# artifacts, and future executors copied by Buildroot's overlay merge.
rm -rf "$TARGET_DIR/root/tools"
rm -f "$TARGET_DIR/usr/bin/dcent-shell"

# switch_firmware.{py,sh} are offline U-Boot environment-image transformers,
# not target-side recovery authorities.  Remove both names after every overlay
# and package has run so a warm Buildroot tree or future package cannot restore
# the former raw-environment patcher to a production image.
rm -f "$TARGET_DIR/usr/sbin/switch_firmware.py" \
    "$TARGET_DIR/usr/sbin/switch_firmware.sh"

# Convenience debug binaries (strace, leftover i2c-tools) stay on DEV/LAB
# images (explicit opt-out). RELEASE images — the default posture since
# WS-A4 — must not ship them: dcentrald owns I2C, and strace is a
# research/debug executor, not a product surface. BR2_PACKAGE_STRACE
# remains enabled in dcentos-common.fragment so DEV builds keep the tool.
if dcent_release_posture_is_release; then
    for tool in \
        usr/bin/strace \
        usr/bin/strace-log-merge \
        usr/sbin/strace \
        usr/bin/i2cget \
        usr/bin/i2cset \
        usr/bin/i2cdump \
        usr/bin/i2cdetect \
        usr/bin/i2ctransfer \
        usr/sbin/i2cget \
        usr/sbin/i2cset \
        usr/sbin/i2cdump \
        usr/sbin/i2cdetect \
        usr/sbin/i2ctransfer
    do
        rm -f "$TARGET_DIR/$tool"
    done
fi

# Image-content leak gate (2026-10-06): a RELEASE rootfs must not carry
# internal lab/workspace details (a specific unit's MAC, lab LAN addresses,
# the lab-only home-unit seed, memory-rule slugs, internal doc paths). This is
# the last post-build step of every product defconfig, so it scans the final
# staged rootfs. DEV/LAB images (explicit opt-out) are not gated. Fail closed:
# a missing scanner or interpreter fails the release build.
if dcent_release_posture_is_release; then
    # The board post-build hooks copy the lab-side stock-Bitmain manifest (with
    # internal archive paths) to /etc/dcentos when the build host has it. The
    # daemon never reads that copy: restore_to_stock uses the signed manifest
    # compiled into dcentrald. Drop the unread copy from release rootfs.
    rm -f "$TARGET_DIR/etc/dcentos/stock-bitmain-manifest.json"
    _dcent_leak_scan=""
    if [ -n "${BR2_EXTERNAL_DCENTOS_PATH:-}" ] &&
        [ -f "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/image_content_leak_scan.py" ]; then
        _dcent_leak_scan="${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/image_content_leak_scan.py"
    elif [ -n "${PROJECT_ROOT:-}" ] &&
        [ -f "${PROJECT_ROOT}/scripts/image_content_leak_scan.py" ]; then
        _dcent_leak_scan="${PROJECT_ROOT}/scripts/image_content_leak_scan.py"
    else
        _dcent_leak_self_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
        if [ -f "${_dcent_leak_self_dir}/../../../scripts/image_content_leak_scan.py" ]; then
            _dcent_leak_scan="${_dcent_leak_self_dir}/../../../scripts/image_content_leak_scan.py"
        fi
    fi
    if [ -z "$_dcent_leak_scan" ] || ! command -v python3 >/dev/null 2>&1; then
        echo "prune-runtime-research-tools: image-content leak scanner unavailable; refusing release rootfs" >&2
        exit 1
    fi
    python3 "$_dcent_leak_scan" "$TARGET_DIR" || {
        echo "prune-runtime-research-tools: release rootfs carries internal lab/workspace details (see above)" >&2
        exit 1
    }
fi