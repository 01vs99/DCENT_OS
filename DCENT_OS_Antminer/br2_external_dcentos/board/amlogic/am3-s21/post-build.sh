#!/bin/sh
#
# DCENTos post-build script - capability-first Amlogic A113D native package.
#
# The final overlay owns product identity.  This shared implementation refuses
# every identity that has not been admitted from exact held A113D firmware
# evidence; sibling defconfigs may reuse it without copying the lifecycle code.
#

set -e

TARGET_DIR=$1
BOARD_NAME=$(sed -n 's/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}' \
    "${TARGET_DIR}/etc/dcentos/board_target" 2>/dev/null || true)
case "$BOARD_NAME" in
    am3-s21|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s19kpro) ;;
    *)
        echo "DCENTos A113D post-build: ERROR: unadmitted or missing board_target: ${BOARD_NAME:-<missing>}" >&2
        exit 1
        ;;
esac
PLATFORM_NAME="am3-aml-${BOARD_NAME#am3-}"
LOG_PREFIX="DCENTos post-build (${BOARD_NAME})"

mkdir -p "${TARGET_DIR}/etc"
mkdir -p "${TARGET_DIR}/proc"
mkdir -p "${TARGET_DIR}/sys"
mkdir -p "${TARGET_DIR}/tmp"
mkdir -p "${TARGET_DIR}/root"
mkdir -p "${TARGET_DIR}/root/tools"
mkdir -p "${TARGET_DIR}/root/.ssh"
mkdir -p "${TARGET_DIR}/lib/modules"
mkdir -p "${TARGET_DIR}/usr/local/bin"
mkdir -p "${TARGET_DIR}/var/log"
mkdir -p "${TARGET_DIR}/data"
mkdir -p "${TARGET_DIR}/etc/dcentos"

# W1.5 (2026-05-07): pre-create /data/dcent/ with tight perms (auth.json holder).
mkdir -p "${TARGET_DIR}/data/dcent"
chmod 0700 "${TARGET_DIR}/data/dcent"
chown 0:0 "${TARGET_DIR}/data/dcent" 2>/dev/null || true

chmod +x "${TARGET_DIR}"/etc/init.d/* 2>/dev/null || true

# SSH/dashboard/MCP only. Do not ship BusyBox telnet on am3 images.
rm -f "${TARGET_DIR}/etc/init.d/S50telnet" "${TARGET_DIR}/usr/sbin/telnetd"
rm -f "${TARGET_DIR}/usr/sbin/in.telnetd" "${TARGET_DIR}/usr/bin/telnet"
rm -f "${TARGET_DIR}/etc/default/telnet" 2>/dev/null || true

chmod +x "${TARGET_DIR}"/etc/dcentos-early-init.sh 2>/dev/null || true
chmod +x "${TARGET_DIR}"/root/tools/*.py 2>/dev/null || true
chmod +x "${TARGET_DIR}"/root/tools/*.sh 2>/dev/null || true
chmod +x "${TARGET_DIR}"/usr/bin/dcent-shell 2>/dev/null || true
chmod +x "${TARGET_DIR}"/usr/sbin/sysupgrade 2>/dev/null || true
# W1.1 default-credential lockdown: SSH gate helper must be mode 0755.
chmod 0755 "${TARGET_DIR}"/usr/sbin/dcent-enable-ssh 2>/dev/null || true
chmod +x "${TARGET_DIR}"/root/web/server.py 2>/dev/null || true
chmod +x "${TARGET_DIR}"/root/web/mcp_server.py 2>/dev/null || true

# W5.1 (2026-05-07): install the dashboard SPA at the canonical location
# served by server.py. See DCENT_OS_Antminer/br2_external_dcentos/board/zynq/
# post-build.sh for the full rationale. Single source of truth is
# dashboard/dist/index.html (`cd DCENT_OS_Antminer/dashboard && npm run build`).
DASHBOARD_SRC="${BR2_EXTERNAL_DCENTOS_PATH}/../dashboard/dist/index.html"
DASHBOARD_GZ_SRC="${DASHBOARD_SRC}.gz"
DASHBOARD_SHA_SRC="${DASHBOARD_SRC}.sha256"
DASHBOARD_DEST_DIR="${TARGET_DIR}/usr/share/dcentos-dashboard"
if [ -f "$DASHBOARD_SRC" ]; then
    mkdir -p "$DASHBOARD_DEST_DIR"
    cp "$DASHBOARD_SRC" "$DASHBOARD_DEST_DIR/index.html"
    chmod 644 "$DASHBOARD_DEST_DIR/index.html"
    if [ ! -f "$DASHBOARD_GZ_SRC" ] || [ "$DASHBOARD_SRC" -nt "$DASHBOARD_GZ_SRC" ]; then
        gzip -9 -c "$DASHBOARD_SRC" > "$DASHBOARD_DEST_DIR/index.html.gz"
    else
        cp "$DASHBOARD_GZ_SRC" "$DASHBOARD_DEST_DIR/index.html.gz"
    fi
    if [ ! -f "$DASHBOARD_SHA_SRC" ] || [ "$DASHBOARD_SRC" -nt "$DASHBOARD_SHA_SRC" ]; then
        sha256sum "$DASHBOARD_SRC" | awk '{print $1}' > "$DASHBOARD_DEST_DIR/index.html.sha256"
    else
        cp "$DASHBOARD_SHA_SRC" "$DASHBOARD_DEST_DIR/index.html.sha256"
    fi
    chmod 644 "$DASHBOARD_DEST_DIR/index.html.gz" "$DASHBOARD_DEST_DIR/index.html.sha256"
    DASHBOARD_SIZE=$(stat -c%s "$DASHBOARD_SRC" 2>/dev/null || stat -f%z "$DASHBOARD_SRC")
    echo "${LOG_PREFIX}: installed dashboard SPA ($DASHBOARD_SIZE bytes) at /usr/share/dcentos-dashboard/index.html"
    if [ "$DASHBOARD_SIZE" -lt 100000 ]; then
        echo "${LOG_PREFIX}: ERROR: dashboard appears truncated ($DASHBOARD_SIZE bytes < 100 KB floor)" >&2
        echo "  Run: cd DCENT_OS_Antminer/dashboard && npm run build" >&2
        exit 1
    fi
else
    echo "${LOG_PREFIX}: ERROR: dashboard not found at $DASHBOARD_SRC" >&2
    echo "  Run: cd DCENT_OS_Antminer/dashboard && npm run build" >&2
    exit 1
fi

DCENTOS_INIT="${BR2_EXTERNAL_DCENTOS_PATH}/../dcentrald/target/aarch64-unknown-linux-musl/release/dcentos-init"
if [ -f "$DCENTOS_INIT" ]; then
    rm -f "${TARGET_DIR}/sbin/init" 2>/dev/null || true
    cp "$DCENTOS_INIT" "${TARGET_DIR}/sbin/init"
    chmod 755 "${TARGET_DIR}/sbin/init"
    echo "${LOG_PREFIX}: installed dcentos-init as /sbin/init"
else
    echo "${LOG_PREFIX}: WARNING: dcentos-init not found at $DCENTOS_INIT"
fi

DCENTRALD_BIN="${BR2_EXTERNAL_DCENTOS_PATH}/../dcentrald/target/aarch64-unknown-linux-musl/release/dcentrald"
if [ -f "$DCENTRALD_BIN" ]; then
    STAGED_BIN="${TARGET_DIR}/usr/local/bin/dcentrald"
    cp "$DCENTRALD_BIN" "$STAGED_BIN"
    chmod 755 "$STAGED_BIN"
    DCENTRALD_SIZE=$(stat -c%s "$DCENTRALD_BIN" 2>/dev/null || stat -f%z "$DCENTRALD_BIN")
    echo "${LOG_PREFIX}: installed dcentrald ($DCENTRALD_SIZE bytes)"
else
    echo "${LOG_PREFIX}: ERROR: dcentrald not found at $DCENTRALD_BIN" >&2
    exit 1
fi

STAGED_BIN="${TARGET_DIR}/usr/local/bin/dcentrald"
if [ ! -f "$STAGED_BIN" ]; then
    echo "${LOG_PREFIX}: ERROR: dcentrald missing from $STAGED_BIN" >&2
    exit 1
fi
. "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/dcentrald_version_gate.sh"
dcent_require_dcentrald_version_match \
    "$TARGET_DIR" \
    "$STAGED_BIN" \
    "$LOG_PREFIX" \
    "${BR2_EXTERNAL_DCENTOS_PATH}/../dcentrald/Cargo.toml"

if command -v md5sum > /dev/null 2>&1; then
    md5sum "$STAGED_BIN" | cut -d' ' -f1 > "${TARGET_DIR}/etc/dcentos/dcentrald.md5"
    echo "${LOG_PREFIX}: md5 $(cat "${TARGET_DIR}/etc/dcentos/dcentrald.md5")"
fi

if [ ! -f "${TARGET_DIR}/etc/dcentrald.toml" ]; then
    echo "${LOG_PREFIX}: ERROR: /etc/dcentrald.toml missing from rootfs." >&2
    echo "  Expected board/amlogic/${BOARD_NAME}/rootfs-overlay/etc/dcentrald.toml" >&2
    exit 1
fi

# F-9 (Sweep-v3 PR-086): bare "am3" resolves PLATFORM=unknown in
# S99verify detect_platform() (no `am3` arm; board_target fallback
# skipped because board_family was set). Stamp the SKU-qualified
# `am3-aml-*` form (matches the `am3-aml*` classifier; same value as
# the platform file). The sweep's F-9 named only am3-s19jpro-aml +
# am3-t21; am3-s21 + am3-s19kpro had the identical latent bug.
echo "$PLATFORM_NAME" > "${TARGET_DIR}/etc/dcentos/board_family"
echo "$PLATFORM_NAME" > "${TARGET_DIR}/etc/dcentos/platform"

python3 "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/provision_runtime_policy.py" "$TARGET_DIR"
MUTATION_POLICY=$(tr -d ' \t\r\n' < "${TARGET_DIR}/etc/dcentos/mutation_policy" 2>/dev/null || true)
case "$BOARD_NAME" in
    am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus)
        if ! grep -Fx daemon-hardware "${TARGET_DIR}/etc/dcentos/mutation_policy" >/dev/null; then
            echo "${LOG_PREFIX}: ERROR: native AML beta is missing its generated daemon-hardware capability" >&2
            exit 1
        fi
        ;;
esac

if grep -Fx ota-storage "${TARGET_DIR}/etc/dcentos/mutation_policy" >/dev/null; then
    # The AM3 revert helpers source lib/am3_geometry.sh beside /usr/sbin.
    AM3_GEOMETRY_SRC="${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/am3_geometry.sh"
    if [ -f "$AM3_GEOMETRY_SRC" ]; then
        mkdir -p "${TARGET_DIR}/usr/sbin/lib"
        cp "$AM3_GEOMETRY_SRC" "${TARGET_DIR}/usr/sbin/lib/am3_geometry.sh"
        chmod 644 "${TARGET_DIR}/usr/sbin/lib/am3_geometry.sh" 2>/dev/null || true
        echo "${LOG_PREFIX}: installed am3_geometry.sh for revert helpers"
    else
        echo "${LOG_PREFIX}: WARNING: am3_geometry.sh not found at $AM3_GEOMETRY_SRC" >&2
    fi
else
    echo "${LOG_PREFIX}: management-only target; no AM3 write geometry staged"
fi

#  W12-B: install the per-platform revert script keyed by
# PROFILE_TABLE.amlogic-a113d-bm1368.revert_script (W23 rename). Code-complete but
# `verified_revertable: false` until W20 live test on the office S21.
REVERT_S21_SRC="${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/revert_to_stock_am3_aml_s21.sh"
if [ "$BOARD_NAME" = "am3-s21" ] && [ -f "$REVERT_S21_SRC" ]; then
    cp "$REVERT_S21_SRC" "${TARGET_DIR}/usr/sbin/revert_to_stock_am3_aml_s21.sh"
    chmod +x "${TARGET_DIR}/usr/sbin/revert_to_stock_am3_aml_s21.sh" 2>/dev/null || true
    echo "${LOG_PREFIX}: installed revert_to_stock_am3_aml_s21.sh from scripts/"
elif [ "$BOARD_NAME" = "am3-s21" ]; then
    echo "${LOG_PREFIX}: WARNING: revert_to_stock_am3_aml_s21.sh not found at $REVERT_S21_SRC" >&2
fi

#  W12-B: also ship the stock-Bitmain manifest (parity with
# zynq board post-build). The daemon probes /etc/dcentos/ first.
MANIFEST_SRC="${BR2_EXTERNAL_DCENTOS_PATH}/../../../knowledge-base/firmware-archive/stock-bitmain-manifest.json"
if [ -f "$MANIFEST_SRC" ]; then
    cp "$MANIFEST_SRC" "${TARGET_DIR}/etc/dcentos/stock-bitmain-manifest.json"
    chmod 644 "${TARGET_DIR}/etc/dcentos/stock-bitmain-manifest.json" 2>/dev/null || true
    echo "${LOG_PREFIX}: installed stock-bitmain-manifest.json"
fi

if [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ]; then
    if [ ! -f "${DCENT_RELEASE_PUBKEY_FILE}" ]; then
        echo "${LOG_PREFIX}: ERROR: release public key not found at ${DCENT_RELEASE_PUBKEY_FILE}" >&2
        exit 1
    fi
    cp "${DCENT_RELEASE_PUBKEY_FILE}" "${TARGET_DIR}/etc/dcentos/release_ed25519.pub"
    chmod 644 "${TARGET_DIR}/etc/dcentos/release_ed25519.pub"
elif [ "${DCENT_REQUIRE_RELEASE_KEY:-0}" = "1" ]; then
    echo "${LOG_PREFIX}: ERROR: DCENT_REQUIRE_RELEASE_KEY=1 but DCENT_RELEASE_PUBKEY_FILE is not set" >&2
    exit 1
else
    echo "${LOG_PREFIX}: WARNING: no release public key embedded (package-only image)"
fi

echo "${LOG_PREFIX}: directories, permissions, and board identity set."

# Production-readiness matrix §7 #1 (public-image trust boundary): release-image
# marker + first-boot SSH posture on the RELEASE posture — the DEFAULT since
# WS-A4 (2026-09-01; canonical resolution scripts/lib/release_posture.sh).
# NO-OP on an explicit DEV/LAB opt-out (DCENT_DEV_IMAGE=1).
. "${BR2_EXTERNAL_DCENTOS_PATH}/../scripts/lib/release_image_provision.sh"
dcent_provision_release_image "$TARGET_DIR" "$BOARD_NAME"
