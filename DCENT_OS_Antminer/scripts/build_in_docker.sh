#!/usr/bin/env bash
#
# build_in_docker.sh — One-shot Buildroot + sysupgrade packaging in Docker.
#
# Docker equivalent of build_in_wsl.sh. Uses Dockerfile.build (Ubuntu 22.04
# with Buildroot deps) and a named Docker volume so Buildroot can work on
# a case-sensitive ext4 filesystem — bind-mounting from NTFS breaks the
# build the same way it broke on /mnt/c under WSL.
#
# Release usage (from a bash shell with Docker running):
#
#   cd DCENT_OS_Antminer
#   bash scripts/build_s9_release_capsule.sh
#
# This file is the inner packaging driver. Release admission requires the
# source-snapshot, invocation, sealed Cargo-result, and private release-set
# authorities prepared by build_s9_release_capsule.sh; direct release use is
# rejected.
#
# RELEASE BUILDS (BUG-2, 2026-07-09): export DCENT_MANIFEST_PUBLIC_KEY_HEX
# (64-hex ed25519 verifying key) for BOTH build steps —
# scripts/build-dcentrald.sh (the pin is baked into dcentrald at cargo-build
# time via option_env!) AND this script (validates the env, then Phase 5
# verifies via `strings` that the staged binary actually embeds it).
# Exporting it only here cannot retro-pin an already-built binary;
# build-dcentrald.sh now fails fast if the pin is missing in a release
# context instead of letting Phase 5 fail hours later.
#
# IMAGE POSTURE (WS-A4, 2026-09-01, operator T-OP-7): RELEASE is the DEFAULT.
# A bare invocation builds the hardened customer posture (locked root, no
# skip-password, no MCP autostart, /etc/dcentos/release-image stamped). DEV
# and LAB builds must opt out EXPLICITLY: pass --lab-unsigned (which sets
# DCENT_DEV_IMAGE=1) or export DCENT_DEV_IMAGE=1 / DCENT_RELEASE_IMAGE=0
# yourself. An explicitly-set DCENT_RELEASE_IMAGE always wins over the alias.
#
# TOOLCHAIN SOURCING (BUG-3, 2026-07-09): releases.linaro.org deleted the
# pinned Linaro 7.2-2017.11 binary releases (HTTP 404). Phase 5b sources the
# toolchain from, in order: the persistent in-volume dl-cache
# (/build/DCENT_OS_Antminer/dl-cache/, survives Buildroot re-clones), an
# operator/CI-provided local dir (export DCENT_TOOLCHAIN_LOCAL_DIR=<dir
# containing the tarball> — populate with scripts/provision_build_inputs.sh),
# then network (original URL, then a hash-verified mirror). Every source is
# verified against the recorded SHA256 pin (fail-closed on release builds).
#
# Capsule path (in order):
#   1. Build an invocation-tagged image from the authenticated Dockerfile.
#   2. Create a fresh, exactly labelled invocation Buildroot volume.
#   3. Stage Git-object source bytes without CRLF/mode/version rewrites.
#   4. Stage  into the volume at the path
#      package_sysupgrade.sh probes ($FIRMWARE_DIR/extractions/s9).
#   5. Stage receipt-bound ARM binaries from the sealed result stage into the
#      same layout so the Buildroot overlay picks it up.
#   6. Run `make setup` + `make -j$(nproc)` inside a container.
#   7. Run `package_sysupgrade.sh --board am1-s9 --output /build/out.tar`.
#   8. Copy the complete evidence set only to the private release-set stage;
#      the outer driver seals and atomically promotes that directory.
#

set -euo pipefail

# On Windows/Git-Bash, MSYS rewrites /-prefixed paths before they reach docker,
# which breaks `-v "C:/path:/container"`. Disable conversion for the whole run.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# -------- Target selection (Phase 2 multi-target support) --------
# Default: s9 (am1-s9). Alt: am2-s19jpro (am2-s19j — S19j Pro Zynq variant).
# Keeps the S9 path bit-for-bit identical. Adding `--target am2-s19jpro`
# switches the Buildroot defconfig, package board name, and output filename.
TARGET="s9"
TARGET_EXPLICIT=0
PRODUCER=""
PRODUCER_ARTIFACT_KIND=""
PRODUCER_BOARD=""
OUTPUT_DIR_OVERRIDE=""
LAB_UNSIGNED=0
while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            TARGET_EXPLICIT=1
            TARGET="$2"
            shift 2
            ;;
        --target=*)
            TARGET_EXPLICIT=1
            TARGET="${1#--target=}"
            shift
            ;;
        --producer)
            [ "$#" -ge 2 ] && [ -z "$PRODUCER" ] || { echo "ERROR: exactly one --producer value is required" >&2; exit 2; }
            PRODUCER="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR_OVERRIDE="$2"
            shift 2
            ;;
        --output-dir=*)
            OUTPUT_DIR_OVERRIDE="${1#--output-dir=}"
            shift
            ;;
        --lab-unsigned)
            LAB_UNSIGNED=1
            # WS-A4 (2026-09-01): a lab-unsigned run is a DEV/LAB build.
            # RELEASE is the default image posture now, so declare the
            # canonical DEV opt-out here. An explicitly-exported
            # DCENT_RELEASE_IMAGE still wins over this alias.
            export DCENT_DEV_IMAGE="${DCENT_DEV_IMAGE:-1}"
            shift
            ;;
        -h|--help)
            echo "Usage: $(basename "$0") --producer ID [--output-dir DIR]"
            echo "Authenticated inner packaging driver; use make beta DROP=n for releases."
            echo ""
            echo "Native AM1 producers: am1-s9i am1-s9j am1-s9se am1-s9k am1-s15 am1-t15"
            echo "Other producer IDs are listed by scripts/release_producer.py list."
            echo "Legacy --target recipes include am3-s19kpro-nopic (Unsupported)."
            echo "--lab-unsigned is unavailable in a beta/stable capsule or numbered DROP."
            exit 0
            ;;
        *)
            echo "ERROR: unknown flag: $1 (try --help)" >&2
            exit 1
            ;;
    esac
done

BUILDER_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "$PRODUCER" ]; then
    [ "$TARGET_EXPLICIT" -eq 0 ] || { echo "ERROR: --producer and --target are mutually exclusive" >&2; exit 2; }
    TARGET="$(python3 "$BUILDER_SCRIPT_DIR/release_producer.py" query "$PRODUCER" build_target)"
    PRODUCER_BOARD="$(python3 "$BUILDER_SCRIPT_DIR/release_producer.py" query "$PRODUCER" board_target)"
    PRODUCER_ARTIFACT_KIND="$(python3 "$BUILDER_SCRIPT_DIR/release_producer.py" query "$PRODUCER" artifact_kind)"
fi
if [ -n "${DROP:-}" ] || [ -n "${DCENT_RELEASE_DROP:-}" ]; then
    if [ "$LAB_UNSIGNED" -eq 1 ]; then
        echo "ERROR: unsigned lab output cannot enter a release drop" >&2
        exit 2
    fi
    while IFS= read -r unsigned_name; do
        if [ -n "${!unsigned_name:-}" ] && [ "${!unsigned_name}" != 0 ]; then
            echo "ERROR: $unsigned_name cannot enter a release drop" >&2
            exit 2
        fi
    done < <(compgen -A variable DCENT_ALLOW_UNSIGNED)
fi

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

is_release_status() {
    case "${1:-release}" in
        release|production|beta|stable) return 0 ;;
        *) return 1 ;;
    esac
}

# WS-A4 (2026-09-01, operator T-OP-7): RELEASE is the DEFAULT image posture.
# Resolve the canonical posture once, immediately after argument parsing, and
# materialize it as an explicit DCENT_RELEASE_IMAGE so every downstream read
# in this driver (CE-183 gates, container -e passes, defconfig root-lock,
# release-grade metadata) sees the effective value:
#   * DCENT_RELEASE_IMAGE explicitly set (non-empty) -> that value wins.
#   * else DCENT_DEV_IMAGE=1 (set by --lab-unsigned and by lab/bench
#     callers) -> DEV/LAB posture.
#   * else -> RELEASE (the shipped default).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/release_posture.sh"
DCENT_RELEASE_IMAGE="$(dcent_release_posture_value)"
export DCENT_RELEASE_IMAGE

# BR_DEFCONFIG_FRAGMENTS lists the shared fragments to concatenate BEFORE
# the per-product defconfig at Phase 6 setup. Fragments are space-separated
# and resolved relative to br2_external_dcentos/configs/. Order matters:
# upstream (workspace-wide) first, arch-specific second, per-product last.
# When a key is declared more than once, the LAST occurrence wins because
# `make defconfig` processes the merged file top-to-bottom and a later
# `KEY=value` line overrides an earlier one.
if [ "$TARGET" = "cv1835-s19jpro" ]; then
    echo "ERROR: cv1835-s19jpro has no firmware, sysupgrade, or supported artifact build lane" >&2
    echo "       the evidence-only target remains quarantined pending exact toolchain and containment proof" >&2
    exit 78
fi
case "$TARGET" in
    am1-s9i|am1-s9j|am1-s15|am1-t15|am2-t17e|am2-s17e)
        # Fresh S9 userspace is the common ARM base. The final native hook
        # applies and verifies the exact target's overlays and boot contract.
        BR_DEFCONFIG="dcentos_s9_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="$TARGET"
        TARBALL_NAME="dcentos-sd.img"
        BOARD_POST_IMAGE="native-sd"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    s9)
        BR_DEFCONFIG="dcentos_s9_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am1-s9"
        TARBALL_NAME="dcentos-sysupgrade-118.tar"
        BOARD_POST_IMAGE="internal"  # uses package_sysupgrade.sh explicitly
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am1-s9se)
        # 2026-08-29 packaging-lane wave: the S9 SE research-shell
        # artifact (BoardDesc stays fail-closed - package-only, install
        # denied; the per-board post-image.sh carries the denial metadata).
        BR_DEFCONFIG="dcentos_am1-s9se_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am1-s9se"
        TARBALL_NAME="dcentos-sysupgrade-am1-s9se.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am1-s9k)
        # 2026-08-29 packaging-lane wave: the S9k research-shell
        # artifact (BoardDesc stays fail-closed - package-only, install
        # denied; the per-board post-image.sh carries the denial metadata).
        BR_DEFCONFIG="dcentos_am1-s9k_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am1-s9k"
        TARBALL_NAME="dcentos-sysupgrade-am1-s9k.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-s19jpro)
        BR_DEFCONFIG="dcentos_am2_s19jpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-s19j"
        TARBALL_NAME="dcentos-sysupgrade-am2-s19jpro.tar"
        # For am2, post-image.sh inside the board dir produces the tarball
        # directly (sysupgrade-am2-s19j/ prefix). Phase 7 copies it out.
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-s19jpro-sd)
        #  2026-05-15 Phase 4D: am2 S19j Pro SD-disk
        # variant. Same Buildroot tree as am2-s19jpro (defconfig +
        # BOARD_PKG_NAME + sysupgrade tarball are reused); the post-image
        # step is replaced with build_am2_s19jpro_sd_disk_image.sh which
        # produces a flashable two-partition .img (FAT16 boot + ext2
        # rootfs) for the XIL-class home-lab bring-up flow. Mirrors how
        # am3-bb-s19jpro-vnish wires onto the same defconfig (Phase 1B).
        # Output is the .img in buildroot/output/images/sd_card_am2_s19jpro/.
        BR_DEFCONFIG="dcentos_am2_s19jpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-s19j"
        TARBALL_NAME="dcentos-am2-s19jpro.img"
        BOARD_POST_IMAGE="am2-sd-disk"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    # Added by  Phase 2K (2026-05-15, DevOps-F2):
    # am2-s19pro + am2-s17pro Buildroot variants were created (Phase 2D /
    # Phase 2E) but never wired into this builder — unbuildable until now.
    # Both ride the same Linaro 7.2.1 armv7 toolchain + board-script
    # post-image as am2-s19jpro. The board dir's post-image.sh produces the
    # tarball directly (sysupgrade-<board_target>/ prefix); Phase 7 copies
    # it out.
    am2-s19|am2-t19|am2-s19a|am2-s19plus)
        # Fresh AM2 userspace is composed into an exact signed removable-media
        # profile below. The shared base is never a new-target NAND package.
        [ "$PRODUCER_ARTIFACT_KIND" = native-sd-image ] && [ "$PRODUCER_BOARD" = "$TARGET" ] || {
            echo "ERROR: this exact BM1398 target requires its current native SD producer" >&2
            exit 2
        }
        BR_DEFCONFIG="dcentos_am2_s19jpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="$TARGET"
        TARBALL_NAME="dcentos-sd.img"
        BOARD_POST_IMAGE="native-sd"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-s19pro)
        # S19 / S19 Pro Zynq am2, BM1398 (114 chips/chain). Distinct from
        # am2-s19jpro (BM1362) — the dcentos_am2_s19pro_defconfig uses
        # board_target "am2-s19pro" so a BM1398-only baked image does not
        # collide with the BM1362 am2-s19jpro image. s19jpro cold-boot
        # mining proven 2026-04-10 via /tmp overlay; baked-image live flash
        # still pending.
        BR_DEFCONFIG="dcentos_am2_s19pro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-s19pro"
        TARBALL_NAME="dcentos-sysupgrade-am2-s19pro.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-s17pro)
        # S17 / S17 Pro Zynq am2-s17, BM1397. The exact held Braiins SD donor
        # is selected by source_closure.py, copied into the private build-input
        # snapshot, and passed read-only to post-image.sh. The resulting
        # artifact remains package_only_denied/installable=false: this lane is
        # not stock first-install, Toolbox routing, or device/flash authority.
        # BOARD_PKG_NAME is "am2-s17p" (NOT "am2-s17pro") to match the board
        # post-image.sh BOARD_NAME and the sysupgrade-am2-s17p/ prefix.
        # F-2 (Sweep-v3 PR-079): the canonical defconfig file is
        # `dcentos_am2_s17pro_zynq_defconfig` (its siblings dropped the
        # `_zynq` suffix at creation time; only the S17 Pro one kept it).
        # The arm previously named `dcentos_am2_s17pro_defconfig`, which
        # does not exist — a hard build break for the am2-s17pro target.
        BR_DEFCONFIG="dcentos_am2_s17pro_zynq_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-s17p"
        TARBALL_NAME="dcentos-sysupgrade-am2-s17pro.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    # 2026-08-27 Antminer 17-Series Complete Unlock Armada (agent B2): the
    # remaining BM1397 17-series targets get their own board dirs + defconfigs
    # (clones of am2-s17pro; only board_target + baked geometry differ). The
    # SAME held Braiins am2-s17 SD donor serves the family (A2 section 3), so
    # the donor admission path below is shared with am2-s17pro.
    am2-s17plus)
        BR_DEFCONFIG="dcentos_am2_s17plus_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-s17plus"
        TARBALL_NAME="dcentos-sysupgrade-am2-s17plus.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-t17)
        BR_DEFCONFIG="dcentos_am2_t17_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-t17"
        TARBALL_NAME="dcentos-sysupgrade-am2-t17.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am2-t17plus)
        BR_DEFCONFIG="dcentos_am2_t17plus_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am2-t17plus"
        TARBALL_NAME="dcentos-sysupgrade-am2-t17plus.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    # End Phase 2K
    am3-s19kpro|am3-s19kpro-nopic)
        BR_DEFCONFIG="dcentos_am3_s19kpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19k"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19kpro.tar"
        if [ "$TARGET" = am3-s19kpro-nopic ]; then
            BR_DEFCONFIG="dcentos_am3_s19kpro_nopic_defconfig"
            # The nopic board's overlay/post-build/post-image all emit the
            # am3-s19kpro board identity (its post-image denies install in
            # every mode); the artifact name follows the emitted identity.
            BOARD_PKG_NAME="am3-s19kpro"
            TARBALL_NAME="dcentos-sysupgrade-am3-s19kpro.tar"
        fi
        # am3-aml uses board-script post-image (mkimage uImage CPIO + tar
        # with sysupgrade-am3-s19k/ prefix). Phase H.9 board script.
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s19xp)
        BR_DEFCONFIG="dcentos_am3_s19xp_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19xp"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19xp.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s19jxp)
        BR_DEFCONFIG="dcentos_am3_s19jxp_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19jxp"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19jxp.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s19jproplus)
        BR_DEFCONFIG="dcentos_am3_s19jproplus_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19jproplus"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19jproplus.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    # R10 board join 2026-09-12 (drift13 #6a): the A126 lane joins the typed
    # producer inventory. Its post-image execs the shared am3-bm1362-nopic
    # builder and emits a package_only_denied archive; install stays Denied.
    am3-s19jproa)
        BR_DEFCONFIG="dcentos_am3_s19jproa_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19jproa"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19jproa.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s21)
        BR_DEFCONFIG="dcentos_am3_s21_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s21"
        TARBALL_NAME="dcentos-sysupgrade-am3-s21.tar"
        # am3-aml S21 uses board-script post-image (mkimage uImage CPIO
        # + tar with sysupgrade-am3-s21/ prefix).
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s21pro)
        BR_DEFCONFIG="dcentos_am3_s21pro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s21pro"
        TARBALL_NAME="dcentos-sysupgrade-am3-s21pro.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-s21xp)
        BR_DEFCONFIG="dcentos_am3_s21xp_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s21xp"
        TARBALL_NAME="dcentos-sysupgrade-am3-s21xp.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    # Added by Phase 4B (2026-05-15): am3-AML Buildroot variant fill-in.
    # New per-product carriers on the same A113D Amlogic SoC and 4.9.113
    # kernel. Reuse the am3-aml common fragment + board-script post-image
    # exactly like the existing am3-s21 / am3-s19kpro arms.
    am3-s19jpro-aml)
        # S19j Pro Amlogic (PIC1704 voltage controller at I²C 0x20, BM1362
        # hashboards). Distinct from am2-s19jpro (Zynq am2 / dsPIC). No
        # live unit yet — sysupgrade tarball is build-only.
        BR_DEFCONFIG="dcentos_am3_s19jpro_aml_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-s19jpro-aml"
        TARBALL_NAME="dcentos-sysupgrade-am3-s19jpro-aml.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    am3-t21)
        # T21 — BM1368 Amlogic package scaffold. PIC, PSU, rail, and reset
        # behavior remain unresolved; this target has no mining authority.
        BR_DEFCONFIG="dcentos_am3_t21_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment dcentos_am3_aml_common.fragment"
        BOARD_PKG_NAME="am3-t21"
        TARBALL_NAME="dcentos-sysupgrade-am3-t21.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="aarch64-unknown-linux-musl"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/$TOOLCHAIN_FILE"
        ;;
    # End Phase 4B
    am3-bb)
        BR_DEFCONFIG="dcentos_am3_bb_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am3-bb"
        TARBALL_NAME="dcentos-am3-bb-sdcard.tar"
        # am3-bb uses a board-script post-image that stages an SD-card
        # payload tarball only. It is not a NAND/sysupgrade package.
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am3-bb-s19jpro|am3-bb-s19jpro-payload)
        # W10.11 ( closure): NEW S19j Pro AM335x BB carrier variant
        # per agent B3. NAND install/revert disabled until live /proc/mtd
        # evidence captured (see B3 commit msg). Same A8 toolchain as am3-bb.
        BR_DEFCONFIG="dcentos_am3_bb_s19jpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am3-bb-s19jpro"
        TARBALL_NAME="dcentos-am3-bb-s19jpro-sdcard.tar"
        BOARD_POST_IMAGE="board-script"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    am3-bb-s19jpro-vnish)
        #  2026-05-15 Phase 1B: VNish boot.bin SD prototype
        # variant. Same Buildroot tree as am3-bb-s19jpro (defconfig +
        # BOARD_PKG_NAME + sdcard tarball are reused); the post-image step
        # is replaced with build_am3_bb_sd_vnish_bootbin_image.sh which
        # mirrors VNish v1.2.6's working SD installer flow (boot.bin SD-stage
        # U-Boot loaded at 0x88000000 chaining uImage/DTB/initramfs at the
        # standard AM335x addresses). Output is the .img + manifest in
        # buildroot/output/images/sd_card_am3_bb_s19jpro/.
        BR_DEFCONFIG="dcentos_am3_bb_s19jpro_defconfig"
        BR_DEFCONFIG_FRAGMENTS="dcentos-common.fragment"
        BOARD_PKG_NAME="am3-bb-s19jpro"
        TARBALL_NAME="dcentos-am3-bb-s19jpro-vnish-bootbin.img"
        BOARD_POST_IMAGE="vnish-bootbin-sd"
        BUILD_ARCH="armv7-unknown-linux-musleabihf"
        TOOLCHAIN_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz"
        TOOLCHAIN_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/$TOOLCHAIN_FILE"
        ;;
    *)
        echo "ERROR: unsupported target: $TARGET (see --help for supported targets)" >&2
        exit 1
        ;;
esac

# Immutable Buildroot source identity shared by cold- and warm-volume paths.
if [ -n "$PRODUCER" ]; then
    BOARD_PKG_NAME="$PRODUCER_BOARD"
    TARBALL_NAME="$(python3 "$BUILDER_SCRIPT_DIR/release_producer.py" query "$PRODUCER" primary_artifact)"
    if [ "$PRODUCER_ARTIFACT_KIND" = native-sd-image ]; then
        BOARD_POST_IMAGE=native-sd
    fi
fi
# A warm checkout is never trusted merely because its Makefile exists.
BUILDROOT_REPOSITORY="https://github.com/buildroot/buildroot.git"
BUILDROOT_COMMIT="7c8edc1b402efcd7bba2dabfe0b3be877adaed7a"

dcent_target_requires_dcentos_init() {
    case "$1" in
        s9|am1-s9i|am1-s9j|am1-s9se|am1-s9k|am1-s15|am1-t15|am2-s19jpro|am2-s19jpro-sd|am2-s19pro|am2-s19|am2-t19|am2-s19a|am2-s19plus|am2-s17pro|am2-s17plus|am2-t17|am2-t17plus|am2-t17e|am2-s17e|am3-s19kpro|am3-s19kpro-nopic|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s21|am3-s21pro|am3-s21xp|am3-s19jpro-aml|am3-t21)
            return 0
            ;;
    esac
    return 1
}

dcent_target_requires_dcentos_discovery() {
    case "$1" in
        am1-s9i|am1-s9j|am1-s9se|am1-s9k|am1-s15|am1-t15|am2-s19pro|am2-s19|am2-t19|am2-s19a|am2-s19plus|am2-s17pro|am2-s17plus|am2-t17|am2-t17plus|am2-t17e|am2-s17e)
            return 0
            ;;
        am3-bb|am3-bb-s19jpro|am3-bb-s19jpro-payload|am3-bb-s19jpro-vnish)
            return 0
            ;;
    esac
    return 1
}

# Docker -v cannot take the NT long-path prefix that cygpath -w emits for
# paths beyond the classic MAX_PATH limit; the Docker CLI (Go) handles plain
# long paths itself (2026-09-14 producer).
dcent_cygpath_w() {
    case "$1" in
        /*) R="$(cygpath -m "$1")" ;;
        *)  R="$(cygpath -w "$1" 2>/dev/null || printf '%s\n' "$1")" ;;
    esac
    # cygpath prefixes beyond-MAX_PATH results (\\?\ for -w, //?/ for -m);
    # Docker -v rejects both forms.
    case "$R" in
        [\\][\\][?][\\]*|'//?/'*) R="${R:4}" ;;
    esac
    printf '%s\n' "$R"
}

dcent_validate_docker_transport_path() {
    python3 - "$1" <<'PY'
import sys

value = sys.argv[1]
# The NT long-path prefix is accepted and stripped: downstream Docker -v
# mounts receive the plain native path (observed 2026-09-14 producer: the
# signing-authority stage records \\?\-wrapped paths on the release host).
value = value[4:] if value.startswith("\\\\?\\") else value
if not value or any(character in value for character in ("\0", "\r", "\n")):
    raise SystemExit("unsafe empty/control-character Docker transport path")
windows_drive = (
    len(value) >= 3
    and value[0].isalpha()
    and value[1] == ":"
    and value[2] in ("/", "\\")
)
remainder = value[2:] if windows_drive else value
if ":" in remainder:
    raise SystemExit(f"unsafe colon in Docker transport path: {value!r}")
PY
}

dcent_require_absolute_host_path() {
    case "$1" in
        /*|[A-Za-z]:[\\/]*|\\\\*) return 0 ;;
        *) return 1 ;;
    esac
}

dcent_required_prebuilt_binaries() {
    printf '%s\n' dcentrald
    if dcent_target_requires_dcentos_init "$TARGET"; then
        printf '%s\n' dcentos-init
    fi
    if dcent_target_requires_dcentos_discovery "$TARGET"; then
        printf '%s\n' dcentos-discovery
    fi
}

dcent_expected_build_variant() {
    case "$1" in
        s9|am1-s9i|am1-s9j|am1-s9se|am1-s9k|am1-s15|am1-t15|am2-s19jpro|am2-s19jpro-sd|am2-s19pro|am2-s19|am2-t19|am2-s19a|am2-s19plus|am2-s17pro|am2-s17plus|am2-t17|am2-t17plus|am2-t17e|am2-s17e) printf '%s\n' zynq ;;
        am3-s19kpro|am3-s19kpro-nopic|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s21|am3-s21pro|am3-s21xp|am3-s19jpro-aml|am3-t21) printf '%s\n' amlogic ;;
        # BB packaging currently stages the static musl ARMv7 artifact emitted
        # by the zynq build lane (the standalone `beaglebone` builder targets
        # glibc armv7-unknown-linux-gnueabihf and cannot satisfy BUILD_ARCH).
        am3-bb|am3-bb-s19jpro|am3-bb-s19jpro-payload|am3-bb-s19jpro-vnish) printf '%s\n' zynq ;;
        *) return 1 ;;
    esac
}

dcent_stale_sources_for_binary() {
    binary_path=$1
    binary_name=$2

    find "$PROJECT_DIR/dcentrald" -path '*/target' -prune -o \
        \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
        -newer "$binary_path" -print 2>/dev/null | awk 'NR <= 3 { print }'

    if [ "$binary_name" = "dcentrald" ]; then
        if [ -d "$PROJECT_DIR/dcent-schema" ]; then
            find "$PROJECT_DIR/dcent-schema" -path '*/target' -prune -o \
                \( -name '*.rs' -o -name 'Cargo.toml' \) \
                -newer "$binary_path" -print 2>/dev/null | awk 'NR <= 3 { print }'
        fi
        for baked in \
            "${DCENT_STOCK_MANIFEST_DIR:-$PROJECT_DIR/vendor/stock-manifest}/stock-bitmain-manifest.json" \
            "${DCENT_STOCK_MANIFEST_DIR:-$PROJECT_DIR/vendor/stock-manifest}/stock-bitmain-manifest.json.sig"; do
            if [ -f "$baked" ] && [ "$baked" -nt "$binary_path" ]; then
                printf '%s\n' "$baked"
            fi
        done
    fi
}

dcent_phase0_stale_binary_guard() {
    failed=0
    if [ "$CAPSULE_MODE" = "1" ]; then
        release_dir="$CAPSULE_RESULT_ROOT/target/$BUILD_ARCH/release"
        metadata_file="$CAPSULE_RESULT_ROOT/target/release-inventory/${BUILD_ARCH}.metadata.json"
        toolchain_context="$CAPSULE_RESULT_ROOT/target/release-inventory/${BUILD_ARCH}.toolchain.txt"
        compile_environment="$CAPSULE_RESULT_ROOT/target/release-inventory/${BUILD_ARCH}.compile-env.txt"
    else
        release_dir="$PROJECT_DIR/dcentrald/target/$BUILD_ARCH/release"
        metadata_file="$PROJECT_DIR/dcentrald/target/release-inventory/${BUILD_ARCH}.metadata.json"
        toolchain_context="$PROJECT_DIR/dcentrald/target/release-inventory/${BUILD_ARCH}.toolchain.txt"
        compile_environment="$PROJECT_DIR/dcentrald/target/release-inventory/${BUILD_ARCH}.compile-env.txt"
    fi
    expected_variant=$(dcent_expected_build_variant "$TARGET") || {
        echo "ERROR: no Rust build variant mapping exists for package target $TARGET" >&2
        return 1
    }

    if ! python3 "$SCRIPT_DIR/binary_build_receipt.py" check-override-policy \
        --allow-stale "${DCENT_ALLOW_STALE_DCENTRALD:-0}" \
        --release-provenance "${DCENT_REQUIRE_RELEASE_PROVENANCE:-0}" \
        --release-image "${DCENT_RELEASE_IMAGE:-0}" \
        --package-status "${DCENT_PACKAGE_STATUS:-}"; then
        return 1
    fi

    if [ "$CAPSULE_MODE" != "1" ]; then
        echo "ERROR: packaging prebuilt Rust binaries now requires an invocation capsule" >&2
        echo "       use scripts/build_s9_release_capsule.sh for the migrated S9 release lane" >&2
        return 1
    fi
    export_args=(
        export-snapshot-set
        --git-object-repo "$GIT_OBJECT_REPO"
        --source-snapshot "$CAPSULE_SOURCE_SNAPSHOT"
        --source-commit "$DCENT_SOURCE_COMMIT"
        --source-workspace DCENT_OS_Antminer/dcentrald
        --release-invocation "$CAPSULE_INVOCATION_STAGE"
        --result-root "$CAPSULE_RESULT_ROOT"
        --build-input-snapshot "$CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT"
        --target "$BUILD_ARCH"
        --profile release
        --build-variant "$expected_variant"
        --metadata "$metadata_file"
        --toolchain-context "$toolchain_context"
        --compile-environment "$compile_environment"
        --stage-parent "$BINARY_EXPORT_PARENT"
    )
    if dcent_release_provenance_required; then
        export_args+=(--require-immutable-builder)
    fi

    for binary_name in $(dcent_required_prebuilt_binaries); do
        binary_path="$release_dir/$binary_name"
        if [ ! -f "$binary_path" ]; then
            echo "ERROR: required prebuilt $binary_name binary is missing." >&2
            echo "  expected: $binary_path" >&2
            echo "  Recompile first: bash DCENT_OS_Antminer/scripts/build-dcentrald.sh $BUILD_ARCH" >&2
            failed=1
            continue
        fi

        export_args+=(--pair "$binary_path" "${binary_path}.build-receipt.json")

        # Capsule source is immutable and Git-authenticated; mtimes belong to
        # materialization, not source freshness, so the legacy advisory is not
        # meaningful in this lane.
    done


    if [ "$failed" -ne 0 ]; then
        return "$failed"
    fi

    if ! BINARY_EXPORT_STAGE="$(
        python3 "$SCRIPT_DIR/binary_build_receipt.py" "${export_args[@]}"
    )"; then
        echo "ERROR: immutable prebuilt Rust binary export failed." >&2
        echo "  Recompile first with: bash DCENT_OS_Antminer/scripts/build-dcentrald.sh $expected_variant" >&2
        if is_truthy "${DCENT_ALLOW_STALE_DCENTRALD:-0}"; then
            echo "  DCENT_ALLOW_STALE_DCENTRALD is deprecated and does not bypass receipt/export validation." >&2
        fi
        return 1
    fi
    if ! BINARY_EXPORT_CAPABILITY="$(
        python3 "$SCRIPT_DIR/binary_build_receipt.py" \
            export-snapshot-capability-path --stage "$BINARY_EXPORT_STAGE"
    )"; then
        echo "ERROR: cannot locate the binary export destruction capability." >&2
        return 1
    fi

    return 0
}

dcent_phase0_stale_binary_guard_selftest() {
    selftest_script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    sh "$selftest_script_dir/test_binary_build_receipt.sh"
}

if [ "${DCENT_STALE_BINARY_GUARD_SELFTEST:-0}" = "1" ]; then
    dcent_phase0_stale_binary_guard_selftest
    exit $?
fi

if [ "$LAB_UNSIGNED" = "1" ]; then
    export DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1
    export DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-lab_unsigned}"
fi
DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}"
DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-release}"
if is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE" && is_release_status "$DCENT_PACKAGE_STATUS"; then
    echo "ERROR: DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 requires non-release DCENT_PACKAGE_STATUS (for example lab_unsigned)." >&2
    exit 1
fi
# CE-183: a release-status package must not decouple from release-image
# hardening (SSH root lockdown + /etc/dcentos/release-image marker). Fail fast
# here (seconds) instead of after the 30-90 min Buildroot phase. Since WS-A4
# the RELEASE posture is the default (DCENT_RELEASE_IMAGE is materialized to
# its effective value above), so this fires only on an explicit DEV/LAB
# opt-out (DCENT_DEV_IMAGE=1 / DCENT_RELEASE_IMAGE=0) combined with a
# release-status package.
if is_release_status "$DCENT_PACKAGE_STATUS" && ! is_truthy "${DCENT_RELEASE_IMAGE:-0}"; then
    echo "ERROR: release-status package (DCENT_PACKAGE_STATUS=$DCENT_PACKAGE_STATUS) requires DCENT_RELEASE_IMAGE=1." >&2
    echo "       Release status must not decouple from release-image hardening (CE-183)." >&2
    echo "       Release-root signatures are reserved for fully hardened release profiles." >&2
    echo "       DEV/LAB opt-out: DCENT_DEV_IMAGE=1 (or DCENT_RELEASE_IMAGE=0) with DCENT_PACKAGE_STATUS=lab_unsigned." >&2
    exit 1
fi
# Public/customer firmware tarball gate. Lab/DEV (`--lab-unsigned`, flags
# unset) is unchanged. SCRIPT_DIR is assigned later; locate this file here.
_dcent_scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/public_artifact_release_gate.sh
. "$_dcent_scripts/lib/public_artifact_release_gate.sh"
dcent_require_release_image_for_public_artifact || exit 1
unset _dcent_scripts
if [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
    if ! is_release_status "$DCENT_PACKAGE_STATUS"; then
        echo "ERROR: release-root signing requires release, production, or stable DCENT_PACKAGE_STATUS." >&2
        echo "       Lab and CI artifacts must not inherit persistent-update authority from the release root." >&2
        exit 1
    fi
    if ! is_truthy "${DCENT_RELEASE_IMAGE:-0}" ||
       ! is_truthy "${DCENT_REQUIRE_RELEASE_PROVENANCE:-0}"; then
        echo "ERROR: release-root signing requires release-image hardening and release provenance." >&2
        exit 1
    fi
fi
if [ -z "${DCENT_RELEASE_SIGNING_KEY:-}" ] \
    && ! is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then
    echo "ERROR: release sysupgrade builds require DCENT_RELEASE_SIGNING_KEY." >&2
    echo "       Use --lab-unsigned only for controlled lab packages." >&2
    exit 1
fi

# W1.2 (2026-05-07): manifest pin CI gate. dcentrald-api compiles the
# stock-Bitmain manifest at-rest signature pin in via `option_env!()` on
# `DCENT_MANIFEST_PUBLIC_KEY_HEX` (see dcentrald-api/src/ota_signature.rs).
# When unset at build time, the at-rest pin is silently dropped and the
# binary fails-open on manifest verification — fine for dev work, NOT for
# release. Fail closed unless the operator explicitly opts out via the
# documented dev escape hatch (DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1).
# W4.5 (2026-05-07): the am3-bb carve-out is closed. BB targets now
# require DCENT_MANIFEST_PUBLIC_KEY_HEX + DCENT_RELEASE_SIGNING_KEY just
# like every other target. `--lab-unsigned` (or DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1)
# remains the only escape hatch, and DCENT_PACKAGE_STATUS must be
# non-release for either to be accepted.
if [ -z "${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" ] \
    && ! is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then
    echo "ERROR: release builds require DCENT_MANIFEST_PUBLIC_KEY_HEX (64 hex chars, raw" >&2
    echo "       32-byte ed25519 verifying key) so the at-rest stock-Bitmain manifest" >&2
    echo "       signature pin is baked into the dcentrald binary." >&2
    echo "       See DCENT_OS_Antminer/release/README.md for keypair generation." >&2
    echo "       Dev opt-out: DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 (or --lab-unsigned)." >&2
    exit 1
fi
if [ -n "${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" ]; then
    # Light shape validation (length + hex). The Rust verifier will reject
    # anything that doesn't decode to 32 bytes, but failing here gives the
    # operator a much clearer error than a Buildroot mid-pipeline crash.
    case "${#DCENT_MANIFEST_PUBLIC_KEY_HEX}" in
        64) ;;
        *)
            echo "ERROR: DCENT_MANIFEST_PUBLIC_KEY_HEX must be exactly 64 hex chars" >&2
            echo "       (raw 32-byte ed25519 verifying key). Got ${#DCENT_MANIFEST_PUBLIC_KEY_HEX}." >&2
            exit 1
            ;;
    esac
    if ! printf '%s' "$DCENT_MANIFEST_PUBLIC_KEY_HEX" | grep -qE '^[0-9a-fA-F]{64}$'; then
        echo "ERROR: DCENT_MANIFEST_PUBLIC_KEY_HEX must be 64 hex chars (0-9a-fA-F)." >&2
        exit 1
    fi
    export DCENT_MANIFEST_PUBLIC_KEY_HEX
fi
if [ -n "${DCENT_MANIFEST_KEY_ID:-}" ]; then
    export DCENT_MANIFEST_KEY_ID
fi
export DCENT_ALLOW_UNSIGNED_SYSUPGRADE DCENT_PACKAGE_STATUS

# -------- Config --------
IMAGE_NAME="dcentos-build:latest"
VOLUME_NAME="dcentos-build-work"

# -------- Paths --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"                    # DCENT_OS_Antminer
REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"             # DCENT Projects repo root
GIT_OBJECT_REPO="$REPO_ROOT"
CAPSULE_MODE=0
CAPSULE_SOURCE_SNAPSHOT=""
CAPSULE_SOURCE_TREE=""
CAPSULE_SOURCE_ID=""
CAPSULE_SOURCE_DESCRIPTOR_SHA256=""
CAPSULE_INVOCATION_STAGE=""
CAPSULE_INVOCATION_ID=""
CAPSULE_RESULT_STAGE=""
CAPSULE_RESULT_ROOT=""
CAPSULE_EXTERNAL_INPUT_ROOT=""
CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT=""
CAPSULE_RELEASE_SET_CAPABILITY_FILE=""
CAPSULE_RELEASE_SET_STAGE=""
CAPSULE_PROVENANCE_MOUNT_ARGS=()
if [ "${DCENT_RELEASE_CAPSULE_MODE:-0}" = "1" ]; then
    CAPSULE_MODE=1
    for capsule_variable in \
        DCENT_CAPSULE_GIT_OBJECT_REPO \
        DCENT_CAPSULE_SOURCE_SNAPSHOT \
        DCENT_CAPSULE_SOURCE_COMMIT \
        DCENT_CAPSULE_INVOCATION_STAGE \
        DCENT_CAPSULE_RESULT_STAGE \
        DCENT_CAPSULE_RESULT_ROOT \
        DCENT_CAPSULE_EXTERNAL_INPUT_ROOT \
        DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT \
        DCENT_CAPSULE_RELEASE_SET_CAPABILITY_FILE; do
        if [ -z "${!capsule_variable:-}" ]; then
            echo "ERROR: capsule packaging requires $capsule_variable" >&2
            exit 1
        fi
    done
    GIT_OBJECT_REPO="$DCENT_CAPSULE_GIT_OBJECT_REPO"
    CAPSULE_SOURCE_SNAPSHOT="$DCENT_CAPSULE_SOURCE_SNAPSHOT"
    CAPSULE_INVOCATION_STAGE="$DCENT_CAPSULE_INVOCATION_STAGE"
    CAPSULE_RESULT_STAGE="$DCENT_CAPSULE_RESULT_STAGE"
    CAPSULE_RESULT_ROOT="$DCENT_CAPSULE_RESULT_ROOT"
    CAPSULE_EXTERNAL_INPUT_ROOT="$DCENT_CAPSULE_EXTERNAL_INPUT_ROOT"
    CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT="$DCENT_CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT"
    CAPSULE_RELEASE_SET_CAPABILITY_FILE="$DCENT_CAPSULE_RELEASE_SET_CAPABILITY_FILE"
    CAPSULE_VERIFY_RESULT="$(python3 "$SCRIPT_DIR/source_snapshot.py" \
        verify-against-git \
        --repo-root "$GIT_OBJECT_REPO" \
        --commit "$DCENT_CAPSULE_SOURCE_COMMIT" \
        "$CAPSULE_SOURCE_SNAPSHOT")"
    capsule_verified_field() {
        printf '%s\n' "$CAPSULE_VERIFY_RESULT" \
            | python3 "$SCRIPT_DIR/source_snapshot.py" query-verified --field "$1"
    }
    dcent_capsule_shell_path() {
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -u "$1"
        else
            printf '%s\n' "$1"
        fi
    }
    CAPSULE_SOURCE_TREE="$(dcent_capsule_shell_path "$(capsule_verified_field tree)")"
    CAPSULE_SOURCE_ID="$(capsule_verified_field snapshot_id)"
    CAPSULE_SOURCE_DESCRIPTOR_SHA256="$(capsule_verified_field descriptor_sha256)"
    CAPSULE_INVOCATION_ID="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
        --field invocation_id "$CAPSULE_INVOCATION_STAGE")"
    VOLUME_NAME="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
        --field buildroot_volume "$CAPSULE_INVOCATION_STAGE")"
    IMAGE_NAME="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        query-builder-tag "$CAPSULE_INVOCATION_STAGE")"
    EXPECTED_CAPSULE_PROJECT="$(cd "$CAPSULE_SOURCE_TREE/DCENT_OS_Antminer" && pwd)"
    if [ "$PROJECT_DIR" != "$EXPECTED_CAPSULE_PROJECT" ]; then
        echo "ERROR: capsule packaging driver is not executing from the authenticated source snapshot" >&2
        exit 1
    fi
    python3 "$SCRIPT_DIR/release_result_stage.py" verify \
        --invocation-stage "$CAPSULE_INVOCATION_STAGE" \
        "$CAPSULE_RESULT_STAGE" >/dev/null
    VERIFIED_CAPSULE_RESULT_ROOT="$(python3 "$SCRIPT_DIR/release_result_stage.py" query \
        --field result_root \
        --invocation-stage "$CAPSULE_INVOCATION_STAGE" \
        "$CAPSULE_RESULT_STAGE")"
    CAPSULE_RESULT_ROOT="$(dcent_capsule_shell_path "$CAPSULE_RESULT_ROOT")"
    VERIFIED_CAPSULE_RESULT_ROOT="$(dcent_capsule_shell_path "$VERIFIED_CAPSULE_RESULT_ROOT")"
    if [ "$CAPSULE_RESULT_ROOT" != "$VERIFIED_CAPSULE_RESULT_ROOT" ]; then
        echo "ERROR: capsule result root does not match the invocation-bound result stage" >&2
        exit 1
    fi
    CAPSULE_RELEASE_SET_STAGE="$(python3 "$SCRIPT_DIR/release_set_publication.py" query \
        --field stage-path < "$CAPSULE_RELEASE_SET_CAPABILITY_FILE")"
    CAPSULE_RELEASE_SET_STAGE="$(dcent_capsule_shell_path "$CAPSULE_RELEASE_SET_STAGE")"
    python3 "$SCRIPT_DIR/build_input_snapshot.py" verify \
        --target cargo-workspace "$CAPSULE_CARGO_BUILD_INPUT_SNAPSHOT" >/dev/null
    # A linked worktree's .git points outside its source directory. Export the
    # host-resolved shared object database into a minimal read-only repository;
    # the container still reconstructs and verifies the exact commit itself.
    GIT_COMMON_DIR="$(python3 "$SCRIPT_DIR/release_source_git.py" --repo-root "$GIT_OBJECT_REPO" --field git-common-dir)"
    GIT_COMMON_DIR="$(dcent_capsule_shell_path "$GIT_COMMON_DIR")"
    CAPSULE_SOURCE_STAGE="$(dirname -- "$(dcent_capsule_shell_path "$CAPSULE_SOURCE_SNAPSHOT")")"
    if command -v cygpath >/dev/null 2>&1; then
        CAPSULE_SOURCE_STAGE_MOUNT="$(dcent_cygpath_w "$CAPSULE_SOURCE_STAGE")"
        GIT_COMMON_DIR_MOUNT="$(dcent_cygpath_w "$GIT_COMMON_DIR")"
    else
        CAPSULE_SOURCE_STAGE_MOUNT="$CAPSULE_SOURCE_STAGE"
        GIT_COMMON_DIR_MOUNT="$GIT_COMMON_DIR"
    fi
    CAPSULE_PROVENANCE_MOUNT_ARGS=(
        -v "${CAPSULE_SOURCE_STAGE_MOUNT}:/dcentos-source-snapshot-release:ro"
        -v "${GIT_COMMON_DIR_MOUNT}:/dcent-git-object-repo/.git:ro"
        -e GIT_CONFIG_COUNT=1
        -e GIT_CONFIG_KEY_0=safe.directory
        -e GIT_CONFIG_VALUE_0=/dcent-git-object-repo
    )
    DCENT_SOURCE_COMMIT="$DCENT_CAPSULE_SOURCE_COMMIT"
    DCENT_SOURCE_TREE_STATE="exact_git_object_snapshot"
    SOURCE_DATE_EPOCH="$(python3 "$SCRIPT_DIR/release_source_git.py" --repo-root "$GIT_OBJECT_REPO" --field epoch --commit "$DCENT_SOURCE_COMMIT")"
    DCENT_SOURCE_COMMIT_EPOCH="$SOURCE_DATE_EPOCH"
    DCENT_CREATED_AT_UTC="$(python3 - "$SOURCE_DATE_EPOCH" <<'PY'
import datetime
import sys
print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
    DCENT_BUILD_ARCH="$BUILD_ARCH"
    DCENT_TOOLCHAIN_ID="linaro-7.2.1:${TOOLCHAIN_FILE}"
    # Phase 6/post-image consumers identify the build by its Buildroot
    # defconfig (e.g. the am3-s19kpro post-image refuses any other value);
    # an explicit caller override still wins.
    DCENT_BUILD_TARGET="${DCENT_BUILD_TARGET:-$BR_DEFCONFIG}"
    DCENT_REQUIRE_RELEASE_PROVENANCE=1
    DCENT_CAPSULE_PROVENANCE_VERIFIED=1
    export DCENT_SOURCE_COMMIT DCENT_SOURCE_COMMIT_EPOCH
    export DCENT_SOURCE_TREE_STATE SOURCE_DATE_EPOCH
    export DCENT_CREATED_AT_UTC DCENT_BUILD_ARCH DCENT_TOOLCHAIN_ID
    export DCENT_RELEASE_CAPSULE_MODE DCENT_CAPSULE_PROVENANCE_VERIFIED
fi

# Direct packaging used mutable checkout, Cargo, and Buildroot authorities that
# cannot satisfy receipt-v4 lineage. Reject it before provenance scans,
# snapshots, locks, or Docker access; a future lab lane needs its own explicit
# non-release capsule instead of inheriting this production driver.
if [ "$CAPSULE_MODE" != "1" ]; then
    echo "ERROR: direct Buildroot packaging is disabled until a separate lab capsule exists" >&2
    echo "       use scripts/build_s9_release_capsule.sh for the admitted S9 release lane" >&2
    exit 2
fi
# shellcheck source=lib/sd_image_signing_gate.sh
. "$SCRIPT_DIR/lib/sd_image_signing_gate.sh"
. "$SCRIPT_DIR/lib/release_envelope.sh"
dcent_run_docker_resource_spec() {
    local spec_json=$1
    local -a spec_argv=()
    mapfile -d '' -t spec_argv < <(
        printf '%s\n' "$spec_json" \
            | python3 "$SCRIPT_DIR/release_docker_resources.py" \
                emit-argv0 "$CAPSULE_INVOCATION_STAGE"
    )
    if [ "${#spec_argv[@]}" -eq 0 ] || [ "${spec_argv[0]}" != "docker" ]; then
        echo "ERROR: Docker resource helper emitted no executable exact argv" >&2
        return 1
    fi
    "${spec_argv[@]}"
}
KB_DIR="${DCENT_SOC_BOOT_DIR:-$PROJECT_DIR/vendor/soc-boot}"
if [ "$CAPSULE_MODE" = "1" ]; then
    WIN_BIN="$CAPSULE_RESULT_ROOT/target/$BUILD_ARCH/release/dcentrald"
    RUST_METADATA_FILE="$CAPSULE_RESULT_ROOT/target/release-inventory/${BUILD_ARCH}.metadata.json"
else
    WIN_BIN="$PROJECT_DIR/dcentrald/target/$BUILD_ARCH/release/dcentrald"
    RUST_METADATA_FILE="$PROJECT_DIR/dcentrald/target/release-inventory/${BUILD_ARCH}.metadata.json"
fi

# Snapshot every target-scoped gitignored payload before Docker can consume it.
command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required for out-of-band build-input snapshotting" >&2
    exit 1
}
DCENT_REQUIRE_RELEASE_PROVENANCE="${DCENT_REQUIRE_RELEASE_PROVENANCE:-0}"
if [ "$CAPSULE_MODE" != "1" ]; then
    dcent_prepare_git_release_provenance \
        "$REPO_ROOT" \
        "$DCENT_PACKAGE_STATUS" \
        "$TARGET" \
        "$BUILD_ARCH" \
        "linaro-7.2.1:${TOOLCHAIN_FILE}"
fi
export DCENT_REQUIRE_RELEASE_PROVENANCE
if dcent_release_provenance_required; then
    [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ] || {
        echo "ERROR: release build requires DCENT_RELEASE_SIGNING_KEY" >&2
        exit 1
    }
    [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ] || {
        echo "ERROR: release build requires DCENT_RELEASE_PUBKEY_FILE" >&2
        exit 1
    }
    bash "$SCRIPT_DIR/verify_release_keypair.sh" \
        "$DCENT_RELEASE_SIGNING_KEY" \
        "$DCENT_RELEASE_PUBKEY_FILE" \
        "$DCENT_MANIFEST_PUBLIC_KEY_HEX" >/dev/null
fi
if [ -n "$OUTPUT_DIR_OVERRIDE" ]; then
    case "$OUTPUT_DIR_OVERRIDE" in
        /*|[A-Za-z]:*) OUTPUT_DIR="$OUTPUT_DIR_OVERRIDE" ;;
        *) OUTPUT_DIR="$PROJECT_DIR/$OUTPUT_DIR_OVERRIDE" ;;
    esac
else
    if [ "$CAPSULE_MODE" = "1" ]; then
        echo "ERROR: capsule packaging requires --output-dir for its private release-set stage" >&2
        exit 1
    fi
    OUTPUT_DIR="$PROJECT_DIR/output"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
if [ "$CAPSULE_MODE" = "1" ] && [ "$OUTPUT_DIR" != "$CAPSULE_RELEASE_SET_STAGE" ]; then
    echo "ERROR: capsule output is not the capability-owned release-set stage" >&2
    exit 1
fi

# Capsule packaging owns a fresh capability-bound private release-set stage.
# No inner cleanup is allowed to delete publication pathnames: the outer
# release-set lifecycle either seals and promotes the complete directory or
# destroys the exact owned stage through its capability.
RELEASE_NAME=""
RELEASE_EXT="tar"
case "$TARBALL_NAME" in *.img) RELEASE_EXT="img" ;; esac
RELEASE_GRADE_PATH=""
RELEASE_LAB_PATH=""
RELEASE_METADATA_PATH=""
RELEASE_COPY=""
RELEASE_DATE_STAMP="$(
    printf '%s\n' "$DCENT_CREATED_AT_UTC" \
        | awk -F'T' '{ gsub(/-/, "", $1); print $1 }'
)"
if release_name_candidate="$(
    sh "$SCRIPT_DIR/firmware_release_name.sh" \
        "$TARGET" "${DCENT_RELEASE_CHANNEL:-beta}" "$RELEASE_DATE_STAMP" 2>/dev/null
)"; then
    case "$release_name_candidate" in
        ""|.|..|*/*|*\\*)
            echo "ERROR: firmware release name is not a canonical flat basename" >&2
            exit 1
            ;;
    esac
    RELEASE_NAME="$release_name_candidate"
    RELEASE_GRADE_PATH="$OUTPUT_DIR/${RELEASE_NAME}.${RELEASE_EXT}"
    RELEASE_LAB_PATH="$OUTPUT_DIR/${RELEASE_NAME}-LAB-UNSIGNED-NOT-FOR-RELEASE.${RELEASE_EXT}"
    RELEASE_METADATA_PATH="$OUTPUT_DIR/${RELEASE_NAME}.release.txt"
    dcent_release_require_publication_absent \
        "$OUTPUT_DIR" "$RELEASE_NAME" "$RELEASE_EXT"
else
    if dcent_release_provenance_required; then
        echo "ERROR: release build has no canonical publication name for target '$TARGET'" >&2
        exit 1
    fi
fi

dcent_require_output_absent() {
    output_candidate="$1"
    if [ -e "$output_candidate" ] || [ -L "$output_candidate" ]; then
        echo "ERROR: private release-set stage is not empty at owned output: $output_candidate" >&2
        return 1
    fi
}

dcent_require_prebuilt_rust_sidecars_absent() {
    sidecar_prefix="$1"
    for sidecar_binary in dcentrald dcentos-init dcentos-discovery; do
        dcent_require_output_absent \
            "$OUTPUT_DIR/${sidecar_prefix}.prebuilt-rust.${sidecar_binary}.bin"
        dcent_require_output_absent \
            "$OUTPUT_DIR/${sidecar_prefix}.prebuilt-rust.${sidecar_binary}.build-receipt.json"
    done
}

# Every output slot must be absent in the newly created stage. Refuse any
# collision instead of deleting a pathname whose invocation ownership cannot
# be established locally.
for owned_output in \
    "$OUTPUT_DIR/${TARBALL_NAME}" \
    "$OUTPUT_DIR/${TARBALL_NAME}.manifest.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.rootfs-ownership.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.buildroot-legal.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.rust-dependencies.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.source-closure.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.source-closure.json.sig" \
    "$OUTPUT_DIR/release-packaging-input.json" \
    "$OUTPUT_DIR/${TARBALL_NAME}.sig"; do
    dcent_require_output_absent "$owned_output"
done
dcent_require_prebuilt_rust_sidecars_absent "$TARBALL_NAME"

BUILD_INPUT_STAGE=""
BUILD_INPUT_SNAPSHOT=""
BUILD_INPUT_DESTROY_TOKEN=""
BUILD_INPUT_MOUNT_ARGS=()
AM2_S17_DONOR_ENV_ARGS=()
BINARY_EXPORT_PARENT=""
BINARY_EXPORT_STAGE=""
BINARY_EXPORT_CAPABILITY=""
BINARY_EXPORT_MOUNT_ARGS=()
BINARY_EXPORT_REQUIRED=""
BINARY_EXPORT_DCENTRALD_PATH=""
BINARY_EXPORT_DCENTRALD_SHA256=""
BINARY_EXPORT_INIT_PATH=""
BINARY_EXPORT_INIT_SHA256=""
BINARY_EXPORT_DISCOVERY_PATH=""
BINARY_EXPORT_DISCOVERY_SHA256=""
PREBUILT_RUST_INPUT_ARGS=()
PREBUILT_RUST_INPUT_COUNT=0
CAPSULE_BUILDROOT_VOLUME_CREATED=0
CAPSULE_BUILDROOT_VOLUME_INSPECT=""
CAPSULE_IMAGE_TAG_CREATED=0
CAPSULE_RETAINED_IMAGE_TAG=""

dcent_cleanup_failed_release_evidence() {
    status=$?
    trap - EXIT
    # EXIT cleanup owns only authenticated private authorities and exact Docker
    # resources. Release-set bytes remain under the outer capability lifecycle;
    # this inner process never deletes publication pathnames.
    set +e
    if [ -n "${SIGN_KEY_MOUNT:-}" ] && [ -n "${BUILD_CONTAINER_ID:-}" ]; then
        # The staged 0600 signing-key copy must not outlive this invocation
        # in the warm build volume. Capsule mode destroys the whole volume
        # below; this scrub also covers the persistent warm-volume path and
        # runs on success and failure alike (the trap fires on every exit).
        docker run --rm \
            -v "${VOLUME_NAME}:/build" \
            "$BUILD_CONTAINER_ID" bash -c \
            'rm -f /build/.dcent-release-signing/release-key.pem' >/dev/null 2>&1
    fi
    if [ "$CAPSULE_BUILDROOT_VOLUME_CREATED" = "1" ]; then
        current_volume_inspect="$(docker volume inspect -- "$VOLUME_NAME" 2>/dev/null)"
        if [ -z "$current_volume_inspect" ] || ! printf '%s\n' "$current_volume_inspect" \
            | python3 "$SCRIPT_DIR/release_docker_resources.py" verify-inspect \
                --role buildroot "$CAPSULE_INVOCATION_STAGE" >/dev/null; then
            echo "ERROR: invocation Buildroot volume identity changed before cleanup" >&2
            [ "$status" -ne 0 ] || status=1
        else
            invocation_cleanup_capability="$(python3 "$SCRIPT_DIR/release_invocation.py" query \
                --field capability "$CAPSULE_INVOCATION_STAGE")"
            destroy_volume_spec="$(printf '%s\n' "$current_volume_inspect" \
                | python3 "$SCRIPT_DIR/release_docker_resources.py" destroy-spec \
                    --role buildroot \
                    --capability "$invocation_cleanup_capability" \
                    --empty-or-disposable disposable \
                    "$CAPSULE_INVOCATION_STAGE")"
            if [ -z "$destroy_volume_spec" ] || ! dcent_run_docker_resource_spec \
                "$destroy_volume_spec" >/dev/null; then
                echo "ERROR: failed to remove exact invocation Buildroot volume" >&2
                [ "$status" -ne 0 ] || status=1
            else
                CAPSULE_BUILDROOT_VOLUME_CREATED=0
            fi
        fi
    fi
    if [ "$CAPSULE_IMAGE_TAG_CREATED" = "1" ]; then
        retained_image_id="$(docker image inspect --format '{{.Id}}' \
            "$CAPSULE_RETAINED_IMAGE_TAG" 2>/dev/null)"
        unique_image_id="$(docker image inspect --format '{{.Id}}' \
            "$IMAGE_NAME" 2>/dev/null)"
        if [ -z "$retained_image_id" ] || [ "$retained_image_id" != "$unique_image_id" ]; then
            echo "ERROR: refusing to remove unique builder tag without its retained content-addressed reference" >&2
            [ "$status" -ne 0 ] || status=1
        elif ! docker image rm "$IMAGE_NAME" >/dev/null 2>&1; then
            echo "ERROR: failed to remove exact invocation builder tag" >&2
            [ "$status" -ne 0 ] || status=1
        else
            CAPSULE_IMAGE_TAG_CREATED=0
        fi
    fi
    if [ -n "$BINARY_EXPORT_STAGE" ]; then
        if [ -z "$BINARY_EXPORT_CAPABILITY" ]; then
            BINARY_EXPORT_CAPABILITY="$(
                python3 "$SCRIPT_DIR/binary_build_receipt.py" \
                    export-snapshot-capability-path --stage "$BINARY_EXPORT_STAGE" \
                    2>/dev/null
            )" || true
        fi
        if [ -z "$BINARY_EXPORT_CAPABILITY" ] || ! \
            python3 "$SCRIPT_DIR/binary_build_receipt.py" \
                destroy-export-snapshot-set \
                --stage "$BINARY_EXPORT_STAGE" \
                --capability "$BINARY_EXPORT_CAPABILITY" >/dev/null 2>&1; then
            echo "ERROR: failed to remove private binary export set: $BINARY_EXPORT_STAGE" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    if [ -n "$BINARY_EXPORT_PARENT" ]; then
        capability_directory="$BINARY_EXPORT_PARENT/.dcent-export-capabilities"
        if { [ -e "$capability_directory" ] || [ -L "$capability_directory" ]; } && \
            ! rmdir -- "$capability_directory" 2>/dev/null; then
            echo "ERROR: failed to remove binary export capability directory: $capability_directory" >&2
            [ "$status" -ne 0 ] || status=1
        fi
        if ! rmdir -- "$BINARY_EXPORT_PARENT" 2>/dev/null; then
            echo "ERROR: failed to remove private binary export parent: $BINARY_EXPORT_PARENT" >&2
            [ "$status" -ne 0 ] || status=1
        fi
    fi
    if [ -n "$BUILD_INPUT_SNAPSHOT" ]; then
        python3 "$SCRIPT_DIR/build_input_snapshot.py" destroy \
            --token "$BUILD_INPUT_DESTROY_TOKEN" "$BUILD_INPUT_SNAPSHOT" \
            >/dev/null 2>&1 || {
            echo "ERROR: failed to remove private build-input snapshot: $BUILD_INPUT_STAGE" >&2
            [ "$status" -ne 0 ] || status=1
        }
    fi
    exit "$status"
}
trap dcent_cleanup_failed_release_evidence EXIT

# Materialize target-selected external bytes once. All supported S9/AM2
# consumers below read this private, read-only stage instead of reopening the
# live repository paths declared by the manifest. This does not snapshot or
# claim closure over the project source tree.
BUILD_INPUT_REPO_ROOT="$REPO_ROOT"
if [ "$CAPSULE_MODE" = "1" ]; then
    BUILD_INPUT_REPO_ROOT="$CAPSULE_EXTERNAL_INPUT_ROOT"
fi
BUILD_INPUT_SELECTION_ARGS=()
if [ "$CAPSULE_MODE" = "1" ]; then
    BUILD_INPUT_SELECTION_ARGS=(--selection-root "$REPO_ROOT")
fi
BUILD_INPUT_CREATE_RESULT="$(python3 "$SCRIPT_DIR/build_input_snapshot.py" create \
    --repo-root "$BUILD_INPUT_REPO_ROOT" \
    --held-assets "$(python3 "$SCRIPT_DIR/held_assets.py" --repo-root "$BUILD_INPUT_REPO_ROOT")" \
    --build-input-manifest "$SCRIPT_DIR/build_inputs.manifest" \
    "${BUILD_INPUT_SELECTION_ARGS[@]}" \
    --target "$TARGET")"
snapshot_result_field() {
    printf '%s\n' "$BUILD_INPUT_CREATE_RESULT" \
        | python3 "$SCRIPT_DIR/build_input_snapshot.py" query-result "$@"
}
BUILD_INPUT_STAGE="$(snapshot_result_field --field stage)"
BUILD_INPUT_SNAPSHOT="$(snapshot_result_field --field snapshot)"
BUILD_INPUT_DESTROY_TOKEN="$(snapshot_result_field --field destroy_token)"
if command -v cygpath >/dev/null 2>&1; then
    DOCKER_BUILD_INPUT_STAGE="$(dcent_cygpath_w "$BUILD_INPUT_STAGE")"
else
    DOCKER_BUILD_INPUT_STAGE="$BUILD_INPUT_STAGE"
fi
BUILD_INPUT_MOUNT_ARGS=(
    -v "${DOCKER_BUILD_INPUT_STAGE}:/dcent-inputs:ro"
)
# The ONE held Braiins am2-s17 donor serves the whole BM1397 17 family
# (A2 section 3): S17/S17 Pro/S17+/T17/T17+ share its boot chain.
case "$TARGET" in
    am2-s17pro|am2-s17plus|am2-t17|am2-t17plus)
        AM2_S17_DONOR_RELATIVE_PATH="knowledge-base/firmware-archive/braiins-os_am2-s17_sd.img"
        AM2_S17_DONOR_SNAPSHOT_PATH="${BUILD_INPUT_STAGE}/files/${AM2_S17_DONOR_RELATIVE_PATH}"
        [ -f "$AM2_S17_DONOR_SNAPSHOT_PATH" ] && [ ! -L "$AM2_S17_DONOR_SNAPSHOT_PATH" ] || {
            echo "ERROR: admitted AM2 S17 donor is absent from the private build-input snapshot" >&2
            exit 1
        }
        AM2_S17_DONOR_ENV_ARGS=(
            -e "DCENT_AM2_S17_BRAIINS_SD_IMAGE=/dcent-inputs/files/${AM2_S17_DONOR_RELATIVE_PATH}"
        )
        ;;
esac

# Place the binary export beside the already Docker-shareable out-of-band
# snapshot, but in its own private parent. The export helper owns every entry
# below this directory and cleanup uses its out-of-stage capability.
BINARY_EXPORT_PARENT="$(python3 - "$BUILD_INPUT_STAGE" <<'PY'
import os
from pathlib import Path
import sys
import tempfile

shareable_parent = Path(sys.argv[1]).parent
private_parent = Path(
    tempfile.mkdtemp(prefix="dcent-binary-export-parent-", dir=shareable_parent)
)
os.chmod(private_parent, 0o700)
print(private_parent)
PY
)"
dcent_validate_docker_transport_path "$BINARY_EXPORT_PARENT" || {
    echo "ERROR: private binary export parent is unsafe for Docker transport" >&2
    exit 1
}

# Release signing keys are host files. Docker build stages must see them via
# stable container paths; passing a Windows/WSL host path through the env is not
# enough because Buildroot post-build/post-image scripts run inside containers.
SIGNING_MOUNT_ARGS=()
PUBKEY_MOUNT_ARGS=()
CONTAINER_RELEASE_SIGNING_KEY="${DCENT_RELEASE_SIGNING_KEY:-}"
CONTAINER_RELEASE_PUBKEY_FILE="${DCENT_RELEASE_PUBKEY_FILE:-}"
if [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
    dcent_require_absolute_host_path "$DCENT_RELEASE_SIGNING_KEY" || {
        echo "ERROR: DCENT_RELEASE_SIGNING_KEY must be an absolute host path" >&2
        exit 1
    }
    if [ ! -f "$DCENT_RELEASE_SIGNING_KEY" ]; then
        echo "ERROR: DCENT_RELEASE_SIGNING_KEY points to missing file: $DCENT_RELEASE_SIGNING_KEY" >&2
        exit 1
    fi
    if command -v cygpath >/dev/null 2>&1; then
        SIGN_KEY_MOUNT="$(dcent_cygpath_w "$DCENT_RELEASE_SIGNING_KEY")"
    else
        SIGN_KEY_MOUNT="$DCENT_RELEASE_SIGNING_KEY"
    fi
    dcent_validate_docker_transport_path "$SIGN_KEY_MOUNT" || {
        echo "ERROR: release signing-key path is unsafe for Docker transport" >&2
        exit 1
    }
    # Docker -v cannot take the NT long-path prefix; the validator already
    # accepted the underlying native path.
    SIGN_KEY_MOUNT="${SIGN_KEY_MOUNT#\\\\?\\}"
    SIGNING_MOUNT_ARGS+=(-v "${SIGN_KEY_MOUNT}:/dcent-release-signing-key.pem:ro")
    CONTAINER_RELEASE_SIGNING_KEY="/dcent-release-signing-key.pem"
fi
if [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ]; then
    dcent_require_absolute_host_path "$DCENT_RELEASE_PUBKEY_FILE" || {
        echo "ERROR: DCENT_RELEASE_PUBKEY_FILE must be an absolute host path" >&2
        exit 1
    }
    if [ ! -f "$DCENT_RELEASE_PUBKEY_FILE" ]; then
        echo "ERROR: DCENT_RELEASE_PUBKEY_FILE points to missing file: $DCENT_RELEASE_PUBKEY_FILE" >&2
        exit 1
    fi
    if command -v cygpath >/dev/null 2>&1; then
        RELEASE_PUBKEY_MOUNT="$(dcent_cygpath_w "$DCENT_RELEASE_PUBKEY_FILE")"
    else
        RELEASE_PUBKEY_MOUNT="$DCENT_RELEASE_PUBKEY_FILE"
    fi
    dcent_validate_docker_transport_path "$RELEASE_PUBKEY_MOUNT" || {
        echo "ERROR: release public-key path is unsafe for Docker transport" >&2
        exit 1
    }
    SIGNING_MOUNT_ARGS+=(-v "${RELEASE_PUBKEY_MOUNT}:/dcent-release-ed25519.pub:ro")
    PUBKEY_MOUNT_ARGS+=(-v "${RELEASE_PUBKEY_MOUNT}:/dcent-release-ed25519.pub:ro")
    CONTAINER_RELEASE_PUBKEY_FILE="/dcent-release-ed25519.pub"
elif [ "${DCENT_REQUIRE_RELEASE_KEY:-0}" = "1" ]; then
    echo "ERROR: DCENT_REQUIRE_RELEASE_KEY=1 but DCENT_RELEASE_PUBKEY_FILE is not set" >&2
    exit 1
fi

# -------- Phase 0: staged binary freshness guard (build-hygiene) --------
# This pipeline stages pre-built Rust binaries (Phase 5) and does not
# recompile them. Fail early if dcentrald, dcentos-init, or BB/CV discovery would
# ship stale or missing.
if ! dcent_phase0_stale_binary_guard; then
    exit 1
fi
dcent_validate_docker_transport_path "$BINARY_EXPORT_STAGE" || {
    echo "ERROR: private binary export stage is unsafe for Docker transport" >&2
    exit 1
}
if command -v cygpath >/dev/null 2>&1; then
    DOCKER_BINARY_EXPORT_STAGE="$(dcent_cygpath_w "$BINARY_EXPORT_STAGE")"
else
    DOCKER_BINARY_EXPORT_STAGE="$BINARY_EXPORT_STAGE"
fi
dcent_validate_docker_transport_path "$DOCKER_BINARY_EXPORT_STAGE" || {
    echo "ERROR: converted binary export stage is unsafe for Docker transport" >&2
    exit 1
}
BINARY_EXPORT_MOUNT_ARGS=(
    -v "${DOCKER_BINARY_EXPORT_STAGE}:/dcent-binaries:ro"
)
for binary_name in $(dcent_required_prebuilt_binaries); do
    binary_export_record="$(
        python3 "$SCRIPT_DIR/binary_build_receipt.py" \
            query-export-snapshot-path \
            --stage "$BINARY_EXPORT_STAGE" \
            --binary-name "$binary_name" \
            --artifact binary \
            --field path-sha256
    )"
    IFS=' ' read -r binary_relative_path binary_sha256 binary_record_extra \
        <<<"$binary_export_record"
    if [ -n "$binary_record_extra" ] || \
        [ "$binary_export_record" != "$binary_relative_path $binary_sha256" ]; then
        echo "ERROR: helper returned a malformed export path/digest record for $binary_name" >&2
        exit 1
    fi
    case "$binary_relative_path" in
        artifacts/[0-9][0-9][0-9][0-9]/"$binary_name") ;;
        *)
            echo "ERROR: helper returned unsafe export path for $binary_name: $binary_relative_path" >&2
            exit 1
            ;;
    esac
    case "$binary_sha256" in
        *[!0-9a-f]*|'')
            echo "ERROR: helper returned malformed SHA256 for $binary_name" >&2
            exit 1
            ;;
    esac
    if [ "${#binary_sha256}" -ne 64 ]; then
        echo "ERROR: helper returned non-64-byte SHA256 for $binary_name" >&2
        exit 1
    fi
    case "$binary_name" in
        dcentrald)
            BINARY_EXPORT_DCENTRALD_PATH="$binary_relative_path"
            BINARY_EXPORT_DCENTRALD_SHA256="$binary_sha256"
            ;;
        dcentos-init)
            BINARY_EXPORT_INIT_PATH="$binary_relative_path"
            BINARY_EXPORT_INIT_SHA256="$binary_sha256"
            ;;
        dcentos-discovery)
            BINARY_EXPORT_DISCOVERY_PATH="$binary_relative_path"
            BINARY_EXPORT_DISCOVERY_SHA256="$binary_sha256"
            ;;
        *)
            echo "ERROR: unsupported required prebuilt binary name: $binary_name" >&2
            exit 1
            ;;
    esac
    if [ -n "$BINARY_EXPORT_REQUIRED" ]; then
        BINARY_EXPORT_REQUIRED="$BINARY_EXPORT_REQUIRED $binary_name"
    else
        BINARY_EXPORT_REQUIRED="$binary_name"
    fi
done

echo "==================================================================="
echo "DCENT_OS Docker build pipeline — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==================================================================="
echo "Project:      $PROJECT_DIR"
echo "Repo root:    $REPO_ROOT"
echo "Image:        $IMAGE_NAME"
echo "Volume:       $VOLUME_NAME"
echo "Prebuilt bin: $WIN_BIN"
echo "Target:       $TARGET"
echo "Defconfig:    $BR_DEFCONFIG"
# F-2 (Sweep-v3 PR-079): fail fast on a TARGET-arm -> defconfig-name
# drift. The per-product defconfig the arm just named must exist under
# the BR2_EXTERNAL configs dir BEFORE the Docker/Buildroot run consumes
# it (the in-Docker fragment merge derives `<base>_full_defconfig` FROM
# it, so a missing base defconfig otherwise fails opaquely deep inside
# Buildroot). POSIX sh (BusyBox ash safe). PROJECT_DIR is resolved above.
if [ ! -f "$PROJECT_DIR/br2_external_dcentos/configs/$BR_DEFCONFIG" ]; then
    echo "ERROR: defconfig '$BR_DEFCONFIG' for target '$TARGET' not found at" >&2
    echo "       $PROJECT_DIR/br2_external_dcentos/configs/$BR_DEFCONFIG" >&2
    echo "       (build_in_docker.sh TARGET arm -> defconfig-name drift; fix the arm)" >&2
    exit 1
fi
echo "Board name:   $BOARD_PKG_NAME"
echo "Output:       $OUTPUT_DIR/$TARBALL_NAME"
echo "Package mode: status=$DCENT_PACKAGE_STATUS allow_unsigned=$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"
echo ""

# -------- Phase 0: sanity --------
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not in PATH"; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERROR: Docker daemon not responding"; exit 1; }
[ -f "$WIN_BIN" ] || { echo "ERROR: prebuilt $BUILD_ARCH binary missing: $WIN_BIN"; exit 1; }
if [ "$CAPSULE_MODE" != "1" ]; then
    [ -d "$KB_DIR" ] || { echo "ERROR: SoC boot inputs missing: $KB_DIR"; echo "       A full flashable image needs non-redistributable boot components"; echo "       (kernel / FPGA / U-Boot). See DEVELOPMENT.md, or flash a prebuilt signed release image."; exit 1; }
    # kernel.bin probe is S9-only. am2-s19jpro and am3-s19kpro use a board
    # post-image.sh that probes its own kernel paths (env override, sibling
    # fallback). Don't fail the host-side sanity gate for them.
    if [ "$BOARD_POST_IMAGE" != "board-script" ]; then
        [ -f "$KB_DIR/kernel.bin" ] || { echo "ERROR: kernel.bin missing in $KB_DIR"; exit 1; }
    fi
fi

# -------- Phase 1: build image --------
echo "--- Phase 1: docker build (cached after first run) ---"
# Docker Desktop on Windows + Git-Bash rejects the /c/... POSIX form for the
# BUILD CONTEXT path (paths with spaces fail). Convert to Windows form via
# cygpath when available; fall back to the original on Linux/macOS.
if command -v cygpath >/dev/null 2>&1; then
    DOCKER_BUILD_CTX="$(dcent_cygpath_w "$PROJECT_DIR")"
    DOCKER_BUILD_DOCKERFILE="$(dcent_cygpath_w "$PROJECT_DIR/Dockerfile.build")"
else
    DOCKER_BUILD_CTX="$PROJECT_DIR"
    DOCKER_BUILD_DOCKERFILE="$PROJECT_DIR/Dockerfile.build"
fi
docker build -f "$DOCKER_BUILD_DOCKERFILE" -t "$IMAGE_NAME" "$DOCKER_BUILD_CTX"
if [ "$CAPSULE_MODE" = "1" ]; then
    CAPSULE_IMAGE_TAG_CREATED=1
fi
BUILD_CONTAINER_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_NAME")"
case "$BUILD_CONTAINER_ID" in
    sha256:[0-9a-f][0-9a-f]*) ;;
    *)
        echo "ERROR: Docker returned a non-immutable build image identity: $BUILD_CONTAINER_ID" >&2
        exit 1
        ;;
esac
if [ "$CAPSULE_MODE" = "1" ]; then
    CAPSULE_RETAINED_IMAGE_TAG="dcentos-build-cache:${BUILD_CONTAINER_ID#sha256:}"
    docker image tag "$BUILD_CONTAINER_ID" "$CAPSULE_RETAINED_IMAGE_TAG"
    [ "$(docker image inspect --format '{{.Id}}' "$CAPSULE_RETAINED_IMAGE_TAG")" = "$BUILD_CONTAINER_ID" ] || {
        echo "ERROR: retained content-addressed builder tag does not name the inspected image" >&2
        exit 1
    }
fi
echo ""

# -------- Phase 2: volume --------
echo "--- Phase 2: volume ---"
if [ "$CAPSULE_MODE" = "1" ]; then
    if docker volume inspect -- "$VOLUME_NAME" >/dev/null 2>&1; then
        echo "ERROR: invocation-scoped Buildroot volume already exists: $VOLUME_NAME" >&2
        exit 1
    fi
    CAPSULE_VOLUME_CREATE_SPEC="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        create-spec --role buildroot "$CAPSULE_INVOCATION_STAGE")"
    dcent_run_docker_resource_spec "$CAPSULE_VOLUME_CREATE_SPEC" >/dev/null
    CAPSULE_BUILDROOT_VOLUME_CREATED=1
    CAPSULE_VOLUME_INSPECT_SPEC="$(python3 "$SCRIPT_DIR/release_docker_resources.py" \
        inspect-spec --role buildroot "$CAPSULE_INVOCATION_STAGE")"
    CAPSULE_BUILDROOT_VOLUME_INSPECT="$(
        dcent_run_docker_resource_spec "$CAPSULE_VOLUME_INSPECT_SPEC"
    )"
    printf '%s\n' "$CAPSULE_BUILDROOT_VOLUME_INSPECT" \
        | python3 "$SCRIPT_DIR/release_docker_resources.py" verify-inspect \
            --role buildroot "$CAPSULE_INVOCATION_STAGE" >/dev/null
    echo "Created fresh invocation-scoped volume: $VOLUME_NAME"
elif docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
    echo "Reusing existing volume: $VOLUME_NAME"
else
    docker volume create "$VOLUME_NAME"
    echo "Created volume: $VOLUME_NAME"
fi
echo ""

# -------- Phase 2b: invalidate cached prebuilt binaries in volume --------
# A persistent volume can hold an older generation from a prior run. Purge the
# Purge every known prebuilt name and receipt before Phase 5 so target switching or a
# partial staging failure cannot expose an undeclared warm-volume generation.
echo "--- Phase 2b: invalidate cached prebuilt binaries in volume ---"
if [ "$CAPSULE_MODE" = "1" ]; then
    echo "Fresh capsule volume has no warm prebuilt state to invalidate"
else
docker run --rm \
    -e BUILD_ARCH="$BUILD_ARCH" \
    -e ALL_PREBUILT_BINARIES="dcentrald dcentos-init dcentos-discovery pic-recovery dspic-flash" \
    -v "${VOLUME_NAME}:/build" \
    "$BUILD_CONTAINER_ID" bash -c '
        set -eu
        case "$BUILD_ARCH" in
            armv7-unknown-linux-musleabihf|aarch64-unknown-linux-musl) ;;
            *) echo "ERROR: unsafe BUILD_ARCH for binary staging: $BUILD_ARCH" >&2; exit 1 ;;
        esac
        release_dir=/build
        [ -d "$release_dir" ] && [ ! -L "$release_dir" ] || {
            echo "ERROR: Docker volume root is not a real directory" >&2
            exit 1
        }
        for component in projects dcentos dcentrald target "$BUILD_ARCH" release; do
            next="$release_dir/$component"
            if [ -L "$next" ] || { [ -e "$next" ] && [ ! -d "$next" ]; }; then
                echo "ERROR: unsafe persistent binary staging component: $next" >&2
                exit 1
            fi
            if [ ! -d "$next" ]; then
                mkdir -- "$next"
            fi
            [ -d "$next" ] && [ ! -L "$next" ] || {
                echo "ERROR: binary staging component changed during creation: $next" >&2
                exit 1
            }
            release_dir="$next"
        done
        for binary_name in $ALL_PREBUILT_BINARIES; do
            rm -f -- \
                "$release_dir/$binary_name" \
                "$release_dir/${binary_name}.build-receipt.json"
            echo "  $binary_name cache invalidated (or was already absent)"
        done
    '
fi
echo ""

# Docker Desktop on Windows accepts POSIX-style mounts for bash. Convert the
# Windows paths (which may contain spaces) into POSIX paths docker understands.
# In practice bash on Windows passes "/c/Users/..." which Docker Desktop rewrites
# to the host path, so we use the paths as-is.
POSIX_PROJECT_DIR="$PROJECT_DIR"
POSIX_OUTPUT_DIR="$OUTPUT_DIR"
for docker_transport_path in "$POSIX_PROJECT_DIR" "$POSIX_OUTPUT_DIR"; do
    dcent_validate_docker_transport_path "$docker_transport_path" || {
        echo "ERROR: project/output path is unsafe for Docker transport" >&2
        exit 1
    }
done

# -------- Phase 3: stage project tree into volume --------
echo "--- Phase 3: stage project tree into volume ---"
python3 "$SCRIPT_DIR/release_dashboard.py" verify \
    --source "$PROJECT_DIR/dashboard" --output "$CAPSULE_RESULT_ROOT/dashboard"
DASHBOARD_MOUNT="$CAPSULE_RESULT_ROOT/dashboard"
TOOLBOX_SOURCE_MOUNT="$REPO_ROOT/projects/dcent-toolbox"
if command -v cygpath >/dev/null 2>&1; then
    DASHBOARD_MOUNT="$(dcent_cygpath_w "$DASHBOARD_MOUNT")"
    TOOLBOX_SOURCE_MOUNT="$(dcent_cygpath_w "$TOOLBOX_SOURCE_MOUNT")"
fi
dcent_validate_docker_transport_path "$DASHBOARD_MOUNT"
dcent_validate_docker_transport_path "$TOOLBOX_SOURCE_MOUNT"
# Mirror the WSL script exclude list. Use rsync --delete so removed files
# disappear from the volume too. CRLF strip only our own shell scripts +
# buildroot external config (Windows editors may save with CRLF and bash
# chokes on \r in shebang lines and inside heredocs).
docker run --rm \
    -e CAPSULE_MODE="$CAPSULE_MODE" \
    -e BUILD_ARCH="$BUILD_ARCH" \
    -v "${VOLUME_NAME}:/build" \
    -v "${POSIX_PROJECT_DIR}:/src:ro" \
    -v "${DASHBOARD_MOUNT}:/dcent-dashboard:ro" \
    -v "${TOOLBOX_SOURCE_MOUNT}:/dcent-toolbox-source:ro" \
    "$BUILD_CONTAINER_ID" bash -c '
        set -e
        bash /src/scripts/release_container_stage.sh /src /dcent-toolbox-source /build "$BUILD_ARCH"
        python3 /build/DCENT_OS_Antminer/scripts/release_dashboard.py stage \
            --source /src/dashboard --output /dcent-dashboard \
            --destination /build/DCENT_OS_Antminer/dashboard/dist
        if [ "$CAPSULE_MODE" != "1" ]; then
            # Compatibility-only normalization for the legacy live-tree lane.
            # Capsule releases consume Git-object bytes and modes unchanged.
            find /build/DCENT_OS_Antminer/scripts -type f -name "*.sh" \
                -exec sed -i "s/\r$//" {} + 2>/dev/null || true
            find /build/DCENT_OS_Antminer/br2_external_dcentos -type f \
                \( -name "*.sh" -o -name "S[0-9][0-9]*" -o -name "Config.in" -o -name "*.mk" -o -name "*defconfig*" -o -name "*.fragment" \) \
                -exec sed -i "s/\r$//" {} + 2>/dev/null || true
            chmod +x /build/DCENT_OS_Antminer/scripts/*.sh 2>/dev/null || true
            find /build/DCENT_OS_Antminer/br2_external_dcentos -type f -name "*.sh" \
                -exec chmod +x {} + 2>/dev/null || true
        fi
        DCENTOS_VERSION_FILE="/build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
        DCENTOS_VERSION="$(sed -n "s/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}" "$DCENTOS_VERSION_FILE")"
        [ -n "$DCENTOS_VERSION" ] || { echo "ERROR: empty DCENTOS_VERSION from $DCENTOS_VERSION_FILE" >&2; exit 1; }
        if [ "$CAPSULE_MODE" != "1" ]; then
            for version_path in \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17plus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17plus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9se/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9k/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproa/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproplus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/dcentos-version
            do
                mkdir -p "$(dirname "$version_path")"
                printf "%s\n" "$DCENTOS_VERSION" > "$version_path"
            done
            # Verify the stamped overlays read back the exact version
            # (synchronize AND verify — the board_desc build-driver lane
            # test requires both references per dedicated overlay).
            for version_path in \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17plus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17plus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9se/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am1-s9k/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproa/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jproplus/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/dcentos-version \
                /build/DCENT_OS_Antminer/br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/dcentos-version
            do
                stamped_version="$(sed -n "s/^[[:space:]]*//;s/[[:space:]]*$//;/^$/!{p;q;}" "$version_path")"
                [ "$stamped_version" = "$DCENTOS_VERSION" ] || {
                    echo "ERROR: $version_path reads back [$stamped_version] not [$DCENTOS_VERSION]" >&2
                    exit 1
                }
            done
            echo "Stamped and verified dcentos-version=$DCENTOS_VERSION into staged rootfs overlays"
        else
            echo "Capsule source staged without CRLF, mode, or version rewrites (version=$DCENTOS_VERSION)"
        fi
        echo "Staged $(du -sh /build/DCENT_OS_Antminer | cut -f1) into volume"
    '
echo ""

# -------- Phase 4: admit and stage target-selected external inputs --------
echo "--- Phase 4: admit target-selected external inputs ---"
# Only source-closure-supported targets reach this phase. Every byte comes from
# the exact target snapshot; unpinned fallback directories are intentionally
# unavailable even for lab packaging.
AMLOGIC_EXACT_MODEL=""
case "$TARGET" in
    am3-s19jpro-aml) AMLOGIC_EXACT_MODEL=s19jpro ;;
    am3-s19xp) AMLOGIC_EXACT_MODEL=s19xp ;;
    am3-s19jxp) AMLOGIC_EXACT_MODEL=s19j-xp ;;
    am3-s19jproa) AMLOGIC_EXACT_MODEL=s19jpro-a ;;
    am3-s19jproplus) AMLOGIC_EXACT_MODEL=s19jpro-plus ;;
    am3-s19kpro|am3-s19kpro-nopic) AMLOGIC_EXACT_MODEL=s19kpro ;;
    am3-s21) AMLOGIC_EXACT_MODEL=s21 ;;
    am3-s21pro) AMLOGIC_EXACT_MODEL=s21pro ;;
    am3-s21xp) AMLOGIC_EXACT_MODEL=s21xp ;;
    am3-t21) AMLOGIC_EXACT_MODEL=t21 ;;
esac
AMLOGIC_EXACT_CONTAINER_ROOT=""
if [ -n "$AMLOGIC_EXACT_MODEL" ]; then
    AMLOGIC_EXACT_CONTAINER_ROOT="/dcent-inputs/files/knowledge-base/extractions/vnish-farm/${AMLOGIC_EXACT_MODEL}/vnishfarm-1.2.6-rc5-aml-nand-install"
fi
if [ "$TARGET" = am3-s19kpro-nopic ]; then
    AMLOGIC_EXACT_CONTAINER_ROOT="/dcent-inputs/files/knowledge-base/extractions/re-armada/vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install"
fi
# Pinned mkimage for the native AM2 fabric FIT pin (drop1-20260919-4f5h9mgl
# latent): the pin bytes were built by u-boot 2026.04 commit 5a998ab00758
# (staged 2026-04-14). The capsule container's apt u-boot-tools (2022.01)
# serializes the FIT with 896 structural bytes more, so byte-exact
# reproduction MUST use this binary. No download fallback exists: a wrong
# mkimage build silently produces non-pin bytes.
MKIMAGE_MOUNT_ARGS=()
if [ -n "${DCENT_TOOLCHAIN_LOCAL_DIR:-}" ]; then
    dcent_require_absolute_host_path "$DCENT_TOOLCHAIN_LOCAL_DIR" || {
        echo "ERROR: DCENT_TOOLCHAIN_LOCAL_DIR must be an absolute host path" >&2
        exit 1
    }
    MKIMAGE_PIN_REL="u-boot-2026.04-mkimage/mkimage"
    MKIMAGE_PIN_SHA256="998314bbd994aa5a8d37f089975f727e6500bce207dfda1322da0877c9b4c99d"
    if [ -f "$DCENT_TOOLCHAIN_LOCAL_DIR/$MKIMAGE_PIN_REL" ]; then
        MKIMAGE_PIN_ACTUAL="$(sha256sum "$DCENT_TOOLCHAIN_LOCAL_DIR/$MKIMAGE_PIN_REL" | awk '{print $1}')"
        if [ "$MKIMAGE_PIN_ACTUAL" != "$MKIMAGE_PIN_SHA256" ]; then
            # Present but wrong bytes is a tamper signal: stop every lane.
            echo "ERROR: pinned mkimage sha256 mismatch under DCENT_TOOLCHAIN_LOCAL_DIR:" >&2
            echo "  expected $MKIMAGE_PIN_SHA256" >&2
            echo "  observed $MKIMAGE_PIN_ACTUAL" >&2
            exit 1
        fi
        if command -v cygpath >/dev/null 2>&1; then
            MKIMAGE_LOCAL_MOUNT="$(dcent_cygpath_w "$DCENT_TOOLCHAIN_LOCAL_DIR")"
        else
            MKIMAGE_LOCAL_MOUNT="$DCENT_TOOLCHAIN_LOCAL_DIR"
        fi
        dcent_validate_docker_transport_path "$MKIMAGE_LOCAL_MOUNT" || {
            echo "ERROR: local toolchain path is unsafe for Docker transport" >&2
            exit 1
        }
        MKIMAGE_MOUNT_ARGS=(-v "${MKIMAGE_LOCAL_MOUNT}:/toolchain-local:ro")
        echo "Pinned mkimage verified: $MKIMAGE_PIN_REL ($MKIMAGE_PIN_SHA256)"
    else
        # Absent is a provisioning gap, not a tamper: only the native AM2
        # squashfs lanes need this tool, and they fail closed at Phase 4 with
        # a nameable error, so unrelated lanes keep building.
        echo "WARNING: DCENT_TOOLCHAIN_LOCAL_DIR does not contain $MKIMAGE_PIN_REL:" >&2
        echo "  $DCENT_TOOLCHAIN_LOCAL_DIR" >&2
        echo "  Native AM2 squashfs lanes will refuse at boot staging until it is" >&2
        echo "  provisioned (scripts/provision_build_inputs.sh)." >&2
    fi
fi
docker run --rm \
    -v "${VOLUME_NAME}:/build" \
    "${BUILD_INPUT_MOUNT_ARGS[@]}" \
    "${MKIMAGE_MOUNT_ARGS[@]}" \
    -e DCENT_MKIMAGE="/toolchain-local/u-boot-2026.04-mkimage/mkimage" \
    -e TARGET="$TARGET" \
    -e PRODUCER="$PRODUCER" \
    -e BOARD_POST_IMAGE="$BOARD_POST_IMAGE" \
    -e DCENT_AM3_AML_KERNEL="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/vmlinux.bin}" \
    -e DCENT_AM3_AML_DTB="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/devicetree.dtb}" \
    -e DCENT_AM3_AML_FW_INFO="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/rootfs/etc/fw-info}" \
    "$BUILD_CONTAINER_ID" bash -c '
        set -e
        if [ "$BOARD_POST_IMAGE" = native-sd ]; then
            python3 /build/DCENT_OS_Antminer/scripts/release_stage_boot.py \
                --producer "$PRODUCER" --snapshot-files /dcent-inputs/files \
                --output /build/dcent-native-boot
            exit 0
        fi
        case "$TARGET" in
            s9)
                mkdir -p /build/DCENT_OS_Antminer/extractions/s9
                rsync -a --delete \
                    /dcent-inputs/files/knowledge-base/extractions/s9/ \
                    /build/DCENT_OS_Antminer/extractions/s9/
                echo "Staged s9: $(du -sh /build/DCENT_OS_Antminer/extractions/s9 | cut -f1)"
                ls -la /build/DCENT_OS_Antminer/extractions/s9/kernel.bin
                ;;
            am2-s19jpro|am2-s19jpro-sd|am2-s19pro)
                mkdir -p /build/DCENT_OS_Antminer/extractions/s19j
                rsync -a --delete \
                    /dcent-inputs/files/knowledge-base/extractions/s19j/ \
                    /build/DCENT_OS_Antminer/extractions/s19j/
                echo "Staged s19j: $(du -sh /build/DCENT_OS_Antminer/extractions/s19j | cut -f1)"
                ;;
            am3-s19jpro-aml|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s19kpro|am3-s19kpro-nopic|am3-s21|am3-s21pro|am3-s21xp|am3-t21)
                . /build/DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/require-exact-build-inputs.sh
                dcent_require_exact_amlogic_build_inputs "$TARGET"
                echo "Amlogic inputs remain in the private read-only snapshot for Buildroot"
                ;;
            am3-bb-s19jpro-payload)
                echo "BeagleBone userspace payload consumes no external boot components"
                ;;
            *)
                echo "ERROR: target $TARGET reached Phase 4 without an exact build-input staging policy" >&2
                exit 1
                ;;
        esac
    '
echo ""

# -------- Phase 5: stage pre-built ARM binary --------
echo "--- Phase 5: stage pre-built dcentrald binary ($BUILD_ARCH) ---"
# Consume only the exact target-required binaries captured by Phase 0. The
# mutable host target tree is deliberately absent from this packaging phase.
# MSYS argv conversion would mangle the multiline inline script at the
# bash->docker.exe exec boundary (observed 2026-09-14: container bash -c
# died at the case-pattern line), so it is disabled for this one spawn.
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
    -e BUILD_ARCH="$BUILD_ARCH" \
    -e TARGET="$TARGET" \
    -e REQUIRED_BINARIES="$BINARY_EXPORT_REQUIRED" \
    -e DCENTRALD_EXPORT_PATH="$BINARY_EXPORT_DCENTRALD_PATH" \
    -e DCENTRALD_EXPORT_SHA256="$BINARY_EXPORT_DCENTRALD_SHA256" \
    -e INIT_EXPORT_PATH="$BINARY_EXPORT_INIT_PATH" \
    -e INIT_EXPORT_SHA256="$BINARY_EXPORT_INIT_SHA256" \
    -e DISCOVERY_EXPORT_PATH="$BINARY_EXPORT_DISCOVERY_PATH" \
    -e DISCOVERY_EXPORT_SHA256="$BINARY_EXPORT_DISCOVERY_SHA256" \
    -e DCENT_MANIFEST_PUBLIC_KEY_HEX="${DCENT_MANIFEST_PUBLIC_KEY_HEX:-}" \
    -e DCENT_ALLOW_UNSIGNED_SYSUPGRADE="$DCENT_ALLOW_UNSIGNED_SYSUPGRADE" \
    "${BINARY_EXPORT_MOUNT_ARGS[@]}" \
    -v "${VOLUME_NAME}:/build" \
    "$BUILD_CONTAINER_ID" bash /build/DCENT_OS_Antminer/scripts/phase5_stage_binaries.sh
echo ""

# -------- Phase 5b: pre-cache Linaro toolchain --------
# Buildroot's wget pulls the ~104 MB Linaro GCC tarball from releases.linaro.org.
# Their S3 throttles long-running slow connections hard (observed 7 KB/s sticky
# state vs 1+ MB/s fresh). Pre-fetching with curl in a short-lived container
# sidesteps the issue and saves hours.
#
# DEVOPS-002 (supply-chain, 2026-06-02): SHA256 PIN + VERIFICATION.
# Previously the only integrity check was a size heuristic
# (`stat -c%s > 100000000`). A size heuristic cannot detect a tampered or
# corrupted toolchain tarball — releases.linaro.org is plain HTTPS off an S3
# bucket with no in-band signature check, so a MITM / mirror-poisoning /
# silent-corruption of the GCC binary that compiles every shipped dcentrald
# would pass undetected. This adds a real cryptographic pin.
#
# The two distinct toolchain artifacts (one per arch) are pinned by file name:
#   - gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz  (armv7 Zynq/BB)
#   - gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz    (aarch64 Amlogic)
#
# Expected hashes are the published Linaro 7.2-2017.11 release checksums
# (releases.linaro.org/components/toolchain/binaries/7.2-2017.11/<arch>/).
# They are recorded here as the SINGLE SOURCE OF TRUTH; the verification step
# computes `sha256sum` of the downloaded tarball and FAILS CLOSED on mismatch.
#
# Release builds enforce the two values below. Confirm each against the upstream
# published checksum exactly once on a clean fetch (for example,
# `curl -fsSL "$TOOLCHAIN_URL" | sha256sum` from a trusted network), then set
# DCENT_TOOLCHAIN_SHA256_VERIFIED=1 so the release evidence records the
# operator-confirmed pin. Dev/lab builds keep the advisory path for iteration;
# release builds fail closed on a missing or mismatched pin.
# ARMHF pin CORRECTED 2026-07-09 (RC rebuild). The prior value
# ba00410f...d4d4f was a stale placeholder that was never operator-verified
# (DCENT_TOOLCHAIN_SHA256_VERIFIED stayed unset because a clean release build
# would have failed it — and did). Linaro's upstream URL now 404s, so the
# authentic checksum was cross-verified against Buildroot's
# toolchain-external-linaro-arm.hash at tags 2018.02 AND 2018.05 (independent),
# both of which pin this exact filename to cee0087b... — matching the on-disk
# toolchain that built the shipped 20260617 beta (xz-integrity + gcc-7.2.1 OK).
TOOLCHAIN_SHA256_ARMHF="cee0087b1f1205b73996651b99acd3a926d136e71047048f1758ffcec69b1ca2"
# Corrected 2026-09-07 during the authorized all-variant beta implementation.
# Buildroot tags 2018.02 and 2018.05 both pin this exact x86_64 archive to
# 20181f82...; the S19k beta lane already uses that value. The old 40dce3d3...
# placeholder could never admit the authentic archive. Retained upstream files:
#
TOOLCHAIN_SHA256_AARCH64="20181f828e1075f1a493947ff91e82dd578ce9f8638fbdfc39e24b62857d8f8d"
case "$TOOLCHAIN_FILE" in
    *arm-linux-gnueabihf*) TOOLCHAIN_SHA256="$TOOLCHAIN_SHA256_ARMHF" ;;
    *aarch64-linux-gnu*)   TOOLCHAIN_SHA256="$TOOLCHAIN_SHA256_AARCH64" ;;
    *)                     TOOLCHAIN_SHA256="" ;;
esac
# W4-5: release/verified builds fail closed on missing or mismatched toolchain
# SHA. The advisory path is only for dev/lab builds.
TOOLCHAIN_SHA256_MANDATORY=0
if dcent_release_provenance_required; then
    TOOLCHAIN_SHA256_MANDATORY=1
    if ! is_truthy "${DCENT_TOOLCHAIN_SHA256_VERIFIED:-0}"; then
        echo "WARNING (DEVOPS-002): release build will enforce the recorded Linaro toolchain SHA256 pin," >&2
        echo "  but DCENT_TOOLCHAIN_SHA256_VERIFIED is unset. Confirm the recorded pin against" >&2
        echo "  the upstream checksum and set DCENT_TOOLCHAIN_SHA256_VERIFIED=1 for release evidence." >&2
    fi
elif is_truthy "${DCENT_TOOLCHAIN_SHA256_VERIFIED:-0}"; then
    TOOLCHAIN_SHA256_MANDATORY=1
fi

# BUG-3 (2026-07-09): releases.linaro.org deleted the 7.2-2017.11 binary
# releases (HTTP 404; sources.buildroot.net and snapshots.linaro.org 404 as
# well), so the network download is now a LAST RESORT — tried against the
# original URL (kept for the record) and then a mirror that was hash-verified
# on 2026-07-09: mirrors.dotsrc.org armbian-dl/_toolchain carries the
# byte-identical armhf artifact (sha256 cee0087b... = the ratified pin; the
# aarch64 sibling there matches Buildroot 2018.02 upstream 20181f82...).
# The RELIABLE sources are:
#   1. the persistent in-volume cache /build/DCENT_OS_Antminer/dl-cache/ (survives
#      Buildroot re-clones — see the BUG-5 restage in Phase 6), and
#   2. an operator/CI-provided local directory:
#        export DCENT_TOOLCHAIN_LOCAL_DIR=<dir containing $TOOLCHAIN_FILE>
#      (populate it with scripts/provision_build_inputs.sh).
# The DEVOPS-002 SHA256 verification below runs on EVERY source (cache,
# local dir, or download) and stays fail-closed for release builds.
TOOLCHAIN_FALLBACK_URL="https://mirrors.dotsrc.org/armbian-dl/_toolchain/${TOOLCHAIN_FILE}"
TOOLCHAIN_LOCAL_MOUNT_ARGS=()
if [ -n "${DCENT_TOOLCHAIN_LOCAL_DIR:-}" ]; then
    dcent_require_absolute_host_path "$DCENT_TOOLCHAIN_LOCAL_DIR" || {
        echo "ERROR: DCENT_TOOLCHAIN_LOCAL_DIR must be an absolute host path" >&2
        exit 1
    }
    if [ -f "$DCENT_TOOLCHAIN_LOCAL_DIR/$TOOLCHAIN_FILE" ]; then
        if command -v cygpath >/dev/null 2>&1; then
            TOOLCHAIN_LOCAL_MOUNT="$(dcent_cygpath_w "$DCENT_TOOLCHAIN_LOCAL_DIR")"
        else
            TOOLCHAIN_LOCAL_MOUNT="$DCENT_TOOLCHAIN_LOCAL_DIR"
        fi
        dcent_validate_docker_transport_path "$TOOLCHAIN_LOCAL_MOUNT" || {
            echo "ERROR: local toolchain path is unsafe for Docker transport" >&2
            exit 1
        }
        TOOLCHAIN_LOCAL_MOUNT_ARGS=(-v "${TOOLCHAIN_LOCAL_MOUNT}:/toolchain-local:ro")
        echo "Toolchain local source: $DCENT_TOOLCHAIN_LOCAL_DIR/$TOOLCHAIN_FILE"
    else
        echo "WARNING: DCENT_TOOLCHAIN_LOCAL_DIR is set but does not contain $TOOLCHAIN_FILE:" >&2
        echo "  $DCENT_TOOLCHAIN_LOCAL_DIR" >&2
        echo "  Falling back to the persistent dl-cache / network download." >&2
    fi
fi

echo "--- Phase 5b: pre-cache Linaro toolchain (if missing) ---"
docker run --rm \
    -e TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -e TOOLCHAIN_URL="$TOOLCHAIN_URL" \
    -e TOOLCHAIN_FALLBACK_URL="$TOOLCHAIN_FALLBACK_URL" \
    -e TOOLCHAIN_SHA256="$TOOLCHAIN_SHA256" \
    -e TOOLCHAIN_SHA256_MANDATORY="$TOOLCHAIN_SHA256_MANDATORY" \
    "${TOOLCHAIN_LOCAL_MOUNT_ARGS[@]}" \
    -v "${VOLUME_NAME}:/build" \
    "$BUILD_CONTAINER_ID" bash -c '
        set -e
        # BUG-3 + BUG-5 (2026-07-09): the toolchain is cached in a persistent
        # dir OUTSIDE buildroot/ so the Phase 6 fresh-clone rm -rf buildroot
        # can no longer delete it (it used to wipe the just-staged tarball on
        # every cold-volume run). Phase 6 (re)stages this cache into
        # buildroot/dl/ after any clone. Sourcing order:
        #   1. persistent cache /build/DCENT_OS_Antminer/dl-cache/toolchain-external-custom
        #   2. legacy warm-volume copy in buildroot/dl (migrated forward)
        #   3. operator-provided DCENT_TOOLCHAIN_LOCAL_DIR (mounted read-only)
        #   4. network download: original Linaro URL (DEAD, 404 — kept for the
        #      record), then the hash-verified dotsrc/armbian mirror.
        PERSIST_DIR="/build/DCENT_OS_Antminer/dl-cache/toolchain-external-custom"
        LEGACY_DIR="/build/DCENT_OS_Antminer/buildroot/dl/toolchain-external-custom"
        FILE="$TOOLCHAIN_FILE"
        mkdir -p "$PERSIST_DIR"

        have_file() { [ -f "$1" ] && [ "$(stat -c%s "$1")" -gt 100000000 ]; }

        if have_file "$PERSIST_DIR/$FILE"; then
            echo "Toolchain already cached: $FILE ($(ls -lh "$PERSIST_DIR/$FILE" | awk "{print \$5}"))"
        elif have_file "$LEGACY_DIR/$FILE"; then
            echo "Migrating cached toolchain from legacy buildroot/dl into persistent dl-cache..."
            ln "$LEGACY_DIR/$FILE" "$PERSIST_DIR/$FILE" 2>/dev/null || cp "$LEGACY_DIR/$FILE" "$PERSIST_DIR/$FILE"
            ls -lh "$PERSIST_DIR/$FILE"
        elif [ -f "/toolchain-local/$FILE" ]; then
            echo "Copying toolchain from DCENT_TOOLCHAIN_LOCAL_DIR (mounted at /toolchain-local)..."
            cp "/toolchain-local/$FILE" "$PERSIST_DIR/$FILE.tmp"
            mv "$PERSIST_DIR/$FILE.tmp" "$PERSIST_DIR/$FILE"
            ls -lh "$PERSIST_DIR/$FILE"
        else
            DOWNLOADED=0
            for TRY_URL in "$TOOLCHAIN_URL" "${TOOLCHAIN_FALLBACK_URL:-}"; do
                [ -n "$TRY_URL" ] || continue
                echo "Downloading toolchain via curl..."
                echo "  $TRY_URL"
                if curl -fL --retry 3 --retry-delay 5 --retry-max-time 600 \
                    -o "$PERSIST_DIR/$FILE.tmp" "$TRY_URL"; then
                    # A HTTP 200 body can still be garbage: the dead
                    # releases.linaro.org URL 301-redirects to a ~60K error
                    # page served with status 200, so curl -f succeeds. Only
                    # accept bodies of plausible toolchain size (same
                    # threshold as have_file above); otherwise try the next
                    # source. DEVOPS-002 below still hash-verifies whatever
                    # lands.
                    BODY_BYTES="$(stat -c%s "$PERSIST_DIR/$FILE.tmp" 2>/dev/null || echo 0)"
                    if [ "$BODY_BYTES" -gt 100000000 ]; then
                        mv "$PERSIST_DIR/$FILE.tmp" "$PERSIST_DIR/$FILE"
                        ls -lh "$PERSIST_DIR/$FILE"
                        DOWNLOADED=1
                        break
                    fi
                    echo "  download body implausibly small (${BODY_BYTES} bytes) from $TRY_URL" >&2
                fi
                rm -f "$PERSIST_DIR/$FILE.tmp"
                echo "  download FAILED from $TRY_URL" >&2
            done
            if [ "$DOWNLOADED" != "1" ]; then
                echo "" >&2
                echo "*** TOOLCHAIN UNAVAILABLE: all download sources failed ***" >&2
                echo "  releases.linaro.org removed the 7.2-2017.11 binary releases (HTTP 404);" >&2
                echo "  sources.buildroot.net and snapshots.linaro.org 404 as well, and the" >&2
                echo "  dotsrc/armbian mirror did not respond. Provide the tarball locally:" >&2
                echo "    1. obtain $FILE" >&2
                echo "       (another DCENT build machine, a previous dcentos-build-work Docker" >&2
                echo "       volume, or run: bash DCENT_OS_Antminer/scripts/provision_build_inputs.sh)" >&2
                echo "    2. export DCENT_TOOLCHAIN_LOCAL_DIR=<dir containing the tarball>" >&2
                echo "    3. re-run this build." >&2
                echo "  Integrity: the SHA256 pin recorded in build_in_docker.sh was cross-verified" >&2
                echo "  against Buildroot toolchain-external-linaro-arm.hash (tags 2018.02 + 2018.05);" >&2
                echo "  whatever you provide is still verified against that pin below" >&2
                echo "  (fail-closed on release builds)." >&2
                exit 1
            fi
        fi

        # DEVOPS-002: cryptographic integrity verification of the toolchain
        # tarball, whatever the source (persistent cache, legacy migration,
        # DCENT_TOOLCHAIN_LOCAL_DIR, or download). The size heuristic above is
        # a fast freshness check; THIS is the security gate.
        if [ -z "${TOOLCHAIN_SHA256:-}" ]; then
            if [ "${TOOLCHAIN_SHA256_MANDATORY:-0}" = "1" ]; then
                echo "ERROR (DEVOPS-002): no expected SHA256 pinned for $FILE; release/verified build fails closed." >&2
                exit 1
            fi
            echo "WARNING (DEVOPS-002): no expected SHA256 pinned for $FILE — integrity NOT verified." >&2
        else
            ACTUAL_SHA256="$(sha256sum "$PERSIST_DIR/$FILE" | awk "{print \$1}")"
            if [ "$ACTUAL_SHA256" = "$TOOLCHAIN_SHA256" ]; then
                echo "OK (DEVOPS-002): toolchain SHA256 verified: $ACTUAL_SHA256"
                if [ "${TOOLCHAIN_SHA256_MANDATORY:-0}" != "1" ]; then
                    # A2e-3: the pin MATCHED but is operator-UNCONFIRMED on this
                    # build (advisory). Surface the exact action so the residual
                    # closes with one operator step.
                    echo "  NOTE (A2e-3): the toolchain matched the RECORDED pin, but that pin is" >&2
                    echo "  not yet operator-confirmed. Confirm $ACTUAL_SHA256" >&2
                    echo "  equals the upstream Linaro published checksum ONCE, then export" >&2
                    echo "  DCENT_TOOLCHAIN_SHA256_VERIFIED=1 so release builds fail-closed on mismatch." >&2
                fi
            else
                echo "" >&2
                echo "*** DEVOPS-002 TOOLCHAIN SHA256 MISMATCH ***" >&2
                echo "  file:     $FILE" >&2
                echo "  expected: $TOOLCHAIN_SHA256" >&2
                echo "  actual:   $ACTUAL_SHA256" >&2
                if [ "${TOOLCHAIN_SHA256_MANDATORY:-0}" = "1" ]; then
                    echo "  FAIL-CLOSED: release/verified build refuses a toolchain that does not match the pin." >&2
                    echo "  If the recorded pin is stale, update TOOLCHAIN_SHA256_ARMHF /" >&2
                    echo "  TOOLCHAIN_SHA256_AARCH64 in build_in_docker.sh against the upstream" >&2
                    echo "  published checksum, then re-run." >&2
                    # Quarantine the mismatching file so a corrected source
                    # (fixed DCENT_TOOLCHAIN_LOCAL_DIR / re-download) is
                    # re-fetched on the next run instead of re-tripping on the
                    # same cached bad copy.
                    mv "$PERSIST_DIR/$FILE" "$PERSIST_DIR/$FILE.badsha256"
                    echo "  Quarantined the mismatching file as $FILE.badsha256 in the dl-cache." >&2
                    exit 1
                else
                    echo "  WARNING: dev/lab build continues (pin not yet operator-verified)." >&2
                    echo "  Set DCENT_TOOLCHAIN_SHA256_VERIFIED=1 once the pin is confirmed to" >&2
                    echo "  make this a hard fail. See the DEVOPS-002 TODO in build_in_docker.sh." >&2
                fi
            fi
        fi

        # Warm-volume convenience: if a real Buildroot checkout already
        # exists, stage the verified tarball into its dl dir now (hardlink —
        # instant, no extra space; cp fallback). Phase 6 also (re)stages
        # after any fresh clone; both paths are idempotent. Deliberately
        # does NOT create buildroot/ here: the old code did (mkdir -p of the
        # dl dir), which left a Makefile-less buildroot/ stub that Phase 6
        # then rm -rf-ed together with the just-staged toolchain (BUG-5).
        if [ -f /build/DCENT_OS_Antminer/buildroot/Makefile ]; then
            mkdir -p "$LEGACY_DIR"
            rm -f "$LEGACY_DIR/.lock"
            if ! have_file "$LEGACY_DIR/$FILE"; then
                ln -f "$PERSIST_DIR/$FILE" "$LEGACY_DIR/$FILE" 2>/dev/null || cp "$PERSIST_DIR/$FILE" "$LEGACY_DIR/$FILE"
                echo "Staged toolchain into existing buildroot/dl: $FILE"
            fi
        fi
    '
echo ""

# -------- Phase 6: Buildroot --------
echo "--- Phase 6: Buildroot make setup + make -j$(docker run --rm "$BUILD_CONTAINER_ID" nproc) ---"
echo "(first build downloads ~500 MB of tarballs — expect 30–90 min)"
if [ -n "${SIGN_KEY_MOUNT:-}" ]; then
    # A bind-mounted Windows host file is visible 0777 inside the container,
    # which trips the runtime-image private-key mode guard. Stage a 0600 copy
    # in the invocation-scoped volume and point the signer at that copy; the
    # bind mount stays read-only. Capsule mode destroys the whole volume at
    # exit; the EXIT trap additionally scrubs the copy for the warm-volume
    # path where the volume itself intentionally persists.
    docker run --rm \
        "${SIGNING_MOUNT_ARGS[@]}" \
        -v "${VOLUME_NAME}:/build" \
        "$BUILD_CONTAINER_ID" bash -c 'set -e; install -D -m 600 /dcent-release-signing-key.pem /build/.dcent-release-signing/release-key.pem'
    CONTAINER_RELEASE_SIGNING_KEY="/build/.dcent-release-signing/release-key.pem"
fi
# Mount the private target-selected input snapshot read-only. Post-image hooks
# receive exact snapshot paths; they cannot reopen mutable repository fallbacks.
phase6_docker_args=()
phase6_docker_args+=(--rm)
phase6_docker_args+=(-e FORCE_UNSAFE_CONFIGURE=1)
phase6_docker_args+=(-e PRODUCER="$PRODUCER")
phase6_docker_args+=(-e DCENT_RELEASE_CHANNEL="${DCENT_RELEASE_CHANNEL:-beta}")
phase6_docker_args+=(-e DCENT_RELEASE_HARDWARE_RECIPE="${DCENT_RELEASE_HARDWARE_RECIPE:-board-default}")
phase6_docker_args+=(-e DCENT_NATIVE_SD_TARGET="${PRODUCER_BOARD}")
phase6_docker_args+=(-e DCENT_RELEASE_DASHBOARD_DIR="/build/DCENT_OS_Antminer/dashboard/dist")
phase6_docker_args+=(-e DCENT_NATIVE_SD_BOOT_INPUTS="/build/dcent-native-boot")
phase6_docker_args+=(-e DCENT_NATIVE_SD_BINARIES="/build/DCENT_OS_Antminer/dcentrald/target/${BUILD_ARCH}/release")
phase6_docker_args+=(-e TARGET="$TARGET")
phase6_docker_args+=(-e BUILD_ARCH="$BUILD_ARCH")
phase6_docker_args+=(-e TOOLCHAIN_FILE="$TOOLCHAIN_FILE")
phase6_docker_args+=(-e BR_DEFCONFIG="$BR_DEFCONFIG")
phase6_docker_args+=(-e BR_DEFCONFIG_FRAGMENTS="$BR_DEFCONFIG_FRAGMENTS")
phase6_docker_args+=(-e BUILDROOT_REPOSITORY="$BUILDROOT_REPOSITORY")
phase6_docker_args+=(-e BUILDROOT_COMMIT="$BUILDROOT_COMMIT")
phase6_docker_args+=(-e DCENT_RELEASE_IMAGE="${DCENT_RELEASE_IMAGE:-0}")
phase6_docker_args+=(-e DCENT_ALLOW_UNSIGNED_SYSUPGRADE="$DCENT_ALLOW_UNSIGNED_SYSUPGRADE")
phase6_docker_args+=(-e DCENT_PACKAGE_STATUS="$DCENT_PACKAGE_STATUS")
phase6_docker_args+=(-e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH")
phase6_docker_args+=(-e DCENT_SOURCE_COMMIT="$DCENT_SOURCE_COMMIT")
phase6_docker_args+=(-e DCENT_SOURCE_COMMIT_EPOCH="$DCENT_SOURCE_COMMIT_EPOCH")
phase6_docker_args+=(-e DCENT_SOURCE_TREE_STATE="$DCENT_SOURCE_TREE_STATE")
phase6_docker_args+=(-e DCENT_BUILD_TARGET="$DCENT_BUILD_TARGET")
phase6_docker_args+=(-e DCENT_BUILD_ARCH="$DCENT_BUILD_ARCH")
phase6_docker_args+=(-e DCENT_TOOLCHAIN_ID="$DCENT_TOOLCHAIN_ID")
phase6_docker_args+=(-e DCENT_REQUIRE_RELEASE_PROVENANCE="$DCENT_REQUIRE_RELEASE_PROVENANCE")
phase6_docker_args+=(-e DCENT_RELEASE_CAPSULE_MODE="$DCENT_RELEASE_CAPSULE_MODE")
phase6_docker_args+=(-e DCENT_CAPSULE_PROVENANCE_VERIFIED="$DCENT_CAPSULE_PROVENANCE_VERIFIED")
phase6_docker_args+=(-e DCENT_PROVENANCE_SOURCE_SNAPSHOT="/dcentos-source-snapshot-release/snapshot.json")
phase6_docker_args+=(-e DCENT_PROVENANCE_GIT_OBJECT_REPO="/dcent-git-object-repo")
phase6_docker_args+=(-e DCENT_PROVENANCE_HELPER="/build/DCENT_OS_Antminer/scripts/source_snapshot.py")
phase6_docker_args+=(-e TOOLCHAIN_SHA256_MANDATORY="$TOOLCHAIN_SHA256_MANDATORY")
phase6_docker_args+=(-e DCENT_RELEASE_SIGNING_KEY="$CONTAINER_RELEASE_SIGNING_KEY")
phase6_docker_args+=(-e DCENT_RELEASE_PUBKEY_FILE="$CONTAINER_RELEASE_PUBKEY_FILE")
phase6_docker_args+=(-e DCENT_REQUIRE_RELEASE_KEY="${DCENT_REQUIRE_RELEASE_KEY:-0}")
phase6_docker_args+=(-e DCENT_AM2_S19J_KERNEL="/dcent-inputs/files/knowledge-base/extractions/s19j/kernel.bin")
phase6_docker_args+=(-e DCENT_AM2_S19J_BITSTREAM="/dcent-inputs/files/knowledge-base/extractions/s19j/fpga_bitstream.bit")
phase6_docker_args+=(-e DCENT_AM2_S19PRO_KERNEL="/dcent-inputs/files/knowledge-base/extractions/s19j/kernel.bin")
phase6_docker_args+=(-e DCENT_AM2_S19PRO_BITSTREAM="/dcent-inputs/files/knowledge-base/extractions/s19j/fpga_bitstream.bit")
phase6_docker_args+=(-e DCENT_AM3_AML_KERNEL="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/vmlinux.bin}")
phase6_docker_args+=(-e DCENT_AM3_AML_DTB="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/devicetree.dtb}")
phase6_docker_args+=(-e DCENT_AM3_AML_FW_INFO="${AMLOGIC_EXACT_CONTAINER_ROOT:+${AMLOGIC_EXACT_CONTAINER_ROOT}/rootfs/etc/fw-info}")
phase6_docker_args+=("${AM2_S17_DONOR_ENV_ARGS[@]}")
phase6_docker_args+=("${SIGNING_MOUNT_ARGS[@]}")
phase6_docker_args+=("${BUILD_INPUT_MOUNT_ARGS[@]}")
phase6_docker_args+=("${CAPSULE_PROVENANCE_MOUNT_ARGS[@]}")
phase6_docker_args+=(-v "${VOLUME_NAME}:/build")
docker run "${phase6_docker_args[@]}" "$BUILD_CONTAINER_ID" bash -c '
        set -e
        # HTTP/1.1 + larger buffer: avoids "RPC failed; curl 92 HTTP/2 stream 0
        # was not closed cleanly" on flaky networks when cloning Buildroot.
        git config --global http.version HTTP/1.1
        git config --global http.postBuffer 524288000
        git config --global http.lowSpeedLimit 1000
        git config --global http.lowSpeedTime 60

        cd /build/DCENT_OS_Antminer

        # ----- Merge shared fragments + per-product defconfig --------------
        # Buildroot has no native top-level fragment mechanism (only the kernel
        # / U-Boot Kconfig recipes do). We materialize a merged defconfig file
        # in-place inside br2_external_dcentos/configs/ named
        # "<base>_full_defconfig". `make defconfig` then consumes that single
        # file, the same way it would consume any other defconfig under the
        # BR2_EXTERNAL configs dir. The fragments are concatenated in the order
        # listed by BR_DEFCONFIG_FRAGMENTS, with the per-product defconfig last
        # so that later overrides win (Kconfig parses top-to-bottom and the
        # last KEY= line wins on conflict).
        CONFIGS_DIR="/build/DCENT_OS_Antminer/br2_external_dcentos/configs"
        FULL_DEFCONFIG_NAME="${BR_DEFCONFIG%_defconfig}_full_defconfig"
        FULL_DEFCONFIG_PATH="${CONFIGS_DIR}/${FULL_DEFCONFIG_NAME}"
        echo "[setup] merging defconfig fragments [$BR_DEFCONFIG_FRAGMENTS] + $BR_DEFCONFIG"
        {
            echo "# === GENERATED by build_in_docker.sh — DO NOT EDIT BY HAND ==="
            echo "# Source: ${BR_DEFCONFIG_FRAGMENTS} ${BR_DEFCONFIG}"
            echo "# Edit the upstream fragments / defconfig instead."
            echo "# ============================================================="
            for frag in $BR_DEFCONFIG_FRAGMENTS; do
                FRAG_PATH="${CONFIGS_DIR}/${frag}"
                [ -f "$FRAG_PATH" ] || { echo "ERROR: fragment missing: $FRAG_PATH" >&2; exit 1; }
                echo ""
                echo "# --- begin fragment: $frag ---"
                cat "$FRAG_PATH"
                echo "# --- end fragment: $frag ---"
            done
            BASE_PATH="${CONFIGS_DIR}/${BR_DEFCONFIG}"
            [ -f "$BASE_PATH" ] || { echo "ERROR: defconfig missing: $BASE_PATH" >&2; exit 1; }
            echo ""
            echo "# --- begin per-product defconfig: $BR_DEFCONFIG ---"
            cat "$BASE_PATH"
            echo "# --- end per-product defconfig: $BR_DEFCONFIG ---"
            # Production-readiness matrix §7 #1 (public-image trust boundary):
            # on a PRODUCTION/RELEASE build (the default posture since WS-A4;
            # DCENT_RELEASE_IMAGE is materialized to its effective value by the
            # outer driver before this container starts) LOCK the root account
            # so NO default SSH password login is possible. This is appended
            # LAST so it overrides the shared dcentos-common.fragment
            # BR2_TARGET_GENERIC_ROOT_PASSWD="dcentral" (Buildroot processes the
            # merged defconfig top-to-bottom; the last KEY= line wins). DEV/LAB
            # builds (explicit opt-out) leave root:dcentral byte-identical — the
            # operator ssh_cmd.js / fleet tooling is unaffected. The matching
            # runtime marker /etc/dcentos/release-image (which disables the
            # dashboard passwordless opt-out) is stamped by the board
            # post-build via scripts/lib/release_image_provision.sh, keyed on
            # the same canonical posture.
            if case "${DCENT_RELEASE_IMAGE:-0}" in 1|true|TRUE|yes|YES|y|Y) true ;; *) false ;; esac; then
                echo ""
                echo "# --- DCENT_RELEASE_IMAGE=1: lock root SSH password login ---"
                # Pinned Buildroot hashes every nonempty non-crypt password,
                # including "*", while root login is enabled. Disable that
                # build-time option to emit the literal locked shadow field.
                # Provisioned Dropbear public-key access is a runtime policy.
                echo "# BR2_TARGET_ENABLE_ROOT_LOGIN is not set"
                echo "BR2_TARGET_GENERIC_ROOT_PASSWD=\"\""
            fi
        } > "$FULL_DEFCONFIG_PATH"
        if [ -n "$PRODUCER" ]; then
            python3 scripts/release_build_config.py --producer "$PRODUCER" --defconfig "$FULL_DEFCONFIG_PATH"
        fi
        echo "[setup] merged defconfig: $FULL_DEFCONFIG_PATH ($(wc -l < "$FULL_DEFCONFIG_PATH") lines)"

        # BUG-5 (2026-07-09): download artifacts must survive a fresh
        # Buildroot clone. The old code rm -rf-ed buildroot/ whenever the
        # Makefile was missing — which, on a cold volume, DELETED the
        # toolchain Phase 5b had just staged into buildroot/dl/ (it only
        # worked when the volume was warm and the clone was skipped). Now:
        # salvage any existing buildroot/dl into the persistent dl-cache
        # BEFORE deleting (hardlinks: instant, no extra space), and (re)stage
        # the persistent cache into buildroot/dl AFTER the clone. Covers
        # cold-volume first runs, warm re-runs, and target switches (the
        # dl-cache accumulates the per-arch toolchains side by side).
        PERSIST_DL_DIR="/build/DCENT_OS_Antminer/dl-cache"
        mkdir -p "$PERSIST_DL_DIR"
        if [ ! -d buildroot ] || [ ! -f buildroot/Makefile ]; then
            echo "[setup] cloning Buildroot (retry up to 4x)"
            if [ -d buildroot/dl ]; then
                echo "[setup] preserving existing buildroot/dl into persistent dl-cache"
                cp -aln buildroot/dl/. "$PERSIST_DL_DIR/" 2>/dev/null || true
            fi
            rm -rf buildroot
            N=1; MAX=4
            while [ $N -le $MAX ]; do
                echo "[clone try $N/$MAX]"
                if git clone "$BUILDROOT_REPOSITORY" buildroot; then break; fi
                rm -rf buildroot
                N=$((N + 1)); sleep 5
            done
            [ -d buildroot ] || { echo "ERROR: clone failed after $MAX tries"; exit 1; }
            ( cd buildroot && git checkout --detach "$BUILDROOT_COMMIT" )
        else
            echo "[setup] Buildroot present"
        fi

        # Source-closure boundary: a persistent Docker volume may contain an
        # old or locally modified checkout. Refuse it before Buildroot can
        # consume source bytes that the release receipt would not describe.
        ACTUAL_BUILDROOT_COMMIT="$(git -C buildroot rev-parse HEAD)"
        [ "$ACTUAL_BUILDROOT_COMMIT" = "$BUILDROOT_COMMIT" ] || {
            echo "ERROR: warm Buildroot checkout is not at the pinned commit" >&2
            echo "  expected: $BUILDROOT_COMMIT" >&2
            echo "  actual:   $ACTUAL_BUILDROOT_COMMIT" >&2
            exit 1
        }
        if [ -n "$(git -C buildroot status --porcelain --untracked-files=normal)" ]; then
            echo "ERROR: Buildroot source tree has modified, staged, or untracked inputs; refusing unbound release input" >&2
            exit 1
        fi

        # BUG-5 (2026-07-09): (re)stage the persistent dl-cache into
        # buildroot/dl — the location Buildroot actually reads (default
        # BR2_DL_DIR). Idempotent: hardlink, no-clobber. Then hard-check the
        # toolchain THIS target needs is really there before spending 30-90
        # minutes in make.
        mkdir -p buildroot/dl
        cp -aln "$PERSIST_DL_DIR/." buildroot/dl/ 2>/dev/null || true
        if [ -n "${TOOLCHAIN_FILE:-}" ] && [ ! -f "buildroot/dl/toolchain-external-custom/$TOOLCHAIN_FILE" ]; then
            echo "ERROR: required toolchain tarball missing from buildroot/dl after staging:" >&2
            echo "  buildroot/dl/toolchain-external-custom/$TOOLCHAIN_FILE" >&2
            echo "  Phase 5b should have cached it in $PERSIST_DL_DIR/toolchain-external-custom/." >&2
            echo "  Re-run the build; if the network download fails (releases.linaro.org is dead)," >&2
            echo "  provide it via DCENT_TOOLCHAIN_LOCAL_DIR=<dir> or run" >&2
            echo "  bash DCENT_OS_Antminer/scripts/provision_build_inputs.sh first." >&2
            exit 1
        fi

        mkdir -p buildroot/output
        STAMP_FILE="buildroot/output/.dcentos-build-target-stamp"
        BR2_EXTERNAL_SOURCE_SHA256="$(python3 scripts/buildroot_local_source_digest.py br2_external_dcentos)"
        if [ "${#BR2_EXTERNAL_SOURCE_SHA256}" -ne 64 ] ||
           [[ "$BR2_EXTERNAL_SOURCE_SHA256" == *[!0-9a-f]* ]]; then
            echo "ERROR: invalid BR2_EXTERNAL source digest: $BR2_EXTERNAL_SOURCE_SHA256" >&2
            exit 1
        fi
        BUILD_DRIVER_SHA256="$(sha256sum scripts/build_in_docker.sh | awk '\''{ print $1 }'\'')"
        SOURCE_DIGEST_TOOL_SHA256="$(sha256sum scripts/buildroot_local_source_digest.py | awk '\''{ print $1 }'\'')"
        DESIRED_STAMP="target=${TARGET:-unknown}|build_arch=${BUILD_ARCH:-unknown}|defconfig=${BR_DEFCONFIG:-unknown}|fragments=${BR_DEFCONFIG_FRAGMENTS:-}"
        DESIRED_STAMP="${DESIRED_STAMP}|br2_external_sha256=$BR2_EXTERNAL_SOURCE_SHA256"
        DESIRED_STAMP="${DESIRED_STAMP}|build_driver_sha256=$BUILD_DRIVER_SHA256"
        DESIRED_STAMP="${DESIRED_STAMP}|source_digest_tool_sha256=$SOURCE_DIGEST_TOOL_SHA256"
        NEED_CLEAN=0
        if [ -f "$STAMP_FILE" ]; then
            CURRENT_STAMP="$(cat "$STAMP_FILE" 2>/dev/null || true)"
            if [ "$CURRENT_STAMP" != "$DESIRED_STAMP" ]; then
                echo "[setup] Buildroot target changed: ${CURRENT_STAMP:-unknown} -> $DESIRED_STAMP"
                NEED_CLEAN=1
            fi
        elif [ -d buildroot/output/target ] || [ -d buildroot/output/build ] || [ -d buildroot/output/images ]; then
            echo "[setup] existing Buildroot output has no DCENT target stamp; cleaning once to prevent cross-target rootfs contamination"
            NEED_CLEAN=1
        fi
        if [ "$NEED_CLEAN" = "1" ]; then
            echo "[setup] running Buildroot clean before applying $FULL_DEFCONFIG_NAME"
            make -C buildroot clean || {
                echo "[setup] Buildroot clean failed; removing generated output subtrees directly" >&2
                rm -rf buildroot/output/build buildroot/output/target buildroot/output/images buildroot/output/staging buildroot/output/host
                mkdir -p buildroot/output
            }
        fi
        printf "%s\n" "$DESIRED_STAMP" > "$STAMP_FILE"

        # The ownership ledger is a per-build receipt. Remove the previous
        # generated sidecar even on a warm same-target build so Phase 7 cannot
        # accidentally collect evidence from an earlier target-tree state if a
        # post-image hook is skipped or regresses.
        rm -f buildroot/output/images/rootfs-ownership.json

        echo "[setup] applying merged defconfig $FULL_DEFCONFIG_NAME"
        make -C buildroot BR2_EXTERNAL=/build/DCENT_OS_Antminer/br2_external_dcentos \
            "$FULL_DEFCONFIG_NAME"

        echo ""
        echo "[build] make -j$(nproc)"
        time make -j$(nproc)

        # Buildroot legal-info is release evidence, not a reusable build
        # product. Delete any warm-volume copy before regeneration so a
        # skipped or failed producer cannot be mistaken for the current build
        # package/source/license observation. The compact inventory is
        # generated and material-reverified later, after the firmware artifact
        # has its final name.
        if [ "$TOOLCHAIN_SHA256_MANDATORY" = "1" ]; then
            echo ""
            echo "[evidence] regenerating Buildroot legal-info"
            # A package dir left half-patched is unrecoverable in Buildroot:
            # every re-entry to its patch step dies on the apply-patches
            # duplicate-filename guard. Two presentations, both poison —
            # .applied_patches_list with .stamp_patched ABSENT (patch step
            # entered, never finished), or .stamp_patched OLDER than its own
            # .stamp_extracted prerequisite (mtime skew re-enters the recipe;
            # critic K, drop1-20260921 was indistinguishable in the log).
            # The legal-info walk can pull packages the main build never
            # stamped (legal-only dependency edges), so sweep the poison
            # state before it turns evidence regeneration into a lane
            # failure (observed: am3-s19jproplus host-python3 3.13.9
            # duplicate 0001-Make-the-build-of-pyc-files-conditional.patch).
            # -mindepth 2 keeps a stray depth-1 list from nuking output/build.
            find buildroot/output/build -mindepth 2 -maxdepth 2 -name .applied_patches_list 2>/dev/null \
                | while read -r applied_list; do
                    package_dir=$(dirname "$applied_list")
                    if [ ! -e "$package_dir/.stamp_patched" ] \
                        || [ "$package_dir/.stamp_patched" -ot "$package_dir/.stamp_extracted" ]; then
                        echo "[evidence] removing unrecoverable half-patched state: $package_dir"
                        rm -rf "$package_dir"
                    fi
                done
            rm -rf buildroot/output/legal-info
            make -C buildroot BR2_EXTERNAL=/build/DCENT_OS_Antminer/br2_external_dcentos legal-info
        fi
    '
echo ""

# -------- Phase 7: package sysupgrade tarball --------
if [ "$BOARD_POST_IMAGE" = "vnish-bootbin-sd" ]; then
    #  2026-05-15 Phase 1B: VNish boot.bin SD prototype
    # variant. The Buildroot post-image produced the standard am3-bb-s19jpro
    # SD payload tarball (rootfs.cpio.gz wrapped uramdisk.image.gz inside);
    # now invoke the VNish-boot.bin-flavored SD .img builder. Reuses the
    # captured LuxOS live boot artifacts for uImage + DTB so we don't depend
    # on a Buildroot kernel build path that hasn't run on this branch.
    echo "--- Phase 7: building VNish boot.bin SD prototype .img for $TARGET ---"
    docker run --rm \
        -v "${VOLUME_NAME}:/build" \
        -v "${POSIX_PROJECT_DIR}:/project:ro" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            cd /build/DCENT_OS_Antminer
            BOOTBIN_REF="/project/output/vnish-extracted-artifacts/boot.bin-s19jpro-bb-v1.2.6"
            LIVE_DIR="/project/output/am3-bb-s19jpro-79-boot-artifacts-LIVE-20260514T214500Z"
            BR_PAYLOAD_DIR="/build/DCENT_OS_Antminer/buildroot/output/images/dcentos-am3-bb-s19jpro-sdcard"
            UIMAGE_PATH=""
            DTB_PATH=""
            INITRAMFS_PATH=""
            if [ -f "$LIVE_DIR/uImage" ]; then
                UIMAGE_PATH="$LIVE_DIR/uImage"
            fi
            if [ -f "$LIVE_DIR/devicetree.dtb" ]; then
                DTB_PATH="$LIVE_DIR/devicetree.dtb"
            fi
            if [ -f "$BR_PAYLOAD_DIR/uramdisk.image.gz" ]; then
                INITRAMFS_PATH="$BR_PAYLOAD_DIR/uramdisk.image.gz"
            elif [ -f "/build/DCENT_OS_Antminer/buildroot/output/images/rootfs.cpio.gz" ]; then
                INITRAMFS_PATH="/build/DCENT_OS_Antminer/buildroot/output/images/rootfs.cpio.gz"
            fi
            [ -n "$UIMAGE_PATH" ] || { echo "ERROR: no uImage source (looked at $LIVE_DIR/uImage)"; exit 1; }
            [ -n "$DTB_PATH" ]    || { echo "ERROR: no DTB source (looked at $LIVE_DIR/devicetree.dtb)"; exit 1; }
            [ -n "$INITRAMFS_PATH" ] || { echo "ERROR: no initramfs source (looked at $BR_PAYLOAD_DIR/uramdisk.image.gz, $BR_PAYLOAD_DIR/../rootfs.cpio.gz)"; exit 1; }
            [ -f "$BOOTBIN_REF" ] || { echo "ERROR: VNish boot.bin reference missing: $BOOTBIN_REF"; exit 1; }
            bash scripts/build_am3_bb_sd_vnish_bootbin_image.sh \
                --bootbin "$BOOTBIN_REF" \
                --uimage "$UIMAGE_PATH" \
                --dtb "$DTB_PATH" \
                --initramfs "$INITRAMFS_PATH"
            SD_OUT_DIR="/build/DCENT_OS_Antminer/buildroot/output/images/sd_card_am3_bb_s19jpro"
            cp "$SD_OUT_DIR/'"$TARBALL_NAME"'" "/build/'"$TARBALL_NAME"'"
            cp "$SD_OUT_DIR/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json" \
               "/build/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json"
            ls -la "/build/'"$TARBALL_NAME"'" "/build/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json"
        '
elif [ "$BOARD_POST_IMAGE" = "am2-sd-disk" ]; then
    #  2026-05-15 Phase 4D: am2 S19j Pro SD-disk variant.
    # The Buildroot post-image produced the standard am2-s19jpro sysupgrade
    # tarball (contains the rootfs squashfs). Now invoke the SD .img builder,
    # which extracts the rootfs from the tarball and stages it into a
    # two-partition .img (FAT16 boot + ext2 rootfs) using sd_common.sh.
    echo "--- Phase 7: building am2-s19jpro SD disk .img for $TARGET ---"
    docker run --rm \
        -v "${VOLUME_NAME}:/build" \
        -v "${POSIX_PROJECT_DIR}:/project:ro" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            cd /build/DCENT_OS_Antminer
            PAYLOAD_TAR="/build/DCENT_OS_Antminer/buildroot/output/images/dcentos-sysupgrade-am2-s19jpro.tar"
            if [ ! -f "$PAYLOAD_TAR" ]; then
                echo "ERROR: expected am2 sysupgrade tarball missing: $PAYLOAD_TAR" >&2
                ls -la /build/DCENT_OS_Antminer/buildroot/output/images/ >&2 || true
                exit 1
            fi
            # --allow-incomplete: a real bootable SD also needs BOOT.bin +
            # uImage + DTB (BraiinsOS am1-s9 SD-recovery feed). The Docker
            # pipeline does NOT carry those artifacts today; the operator
            # composes the bootable card by re-running this script locally
            # with --artifacts <dir> against the captured BraiinsOS feed.
            # This Docker arm produces the rootfs-only staging image so the
            # standard build pipeline always has an artifact to upload.
            bash scripts/build_am2_s19jpro_sd_disk_image.sh \
                --payload-tar "$PAYLOAD_TAR" \
                --allow-incomplete
            SD_OUT_DIR="/build/DCENT_OS_Antminer/buildroot/output/images/sd_card_am2_s19jpro"
            cp "$SD_OUT_DIR/'"$TARBALL_NAME"'" "/build/'"$TARBALL_NAME"'"
            cp "$SD_OUT_DIR/'"$TARBALL_NAME"'.manifest.json" \
               "/build/'"$TARBALL_NAME"'.manifest.json"
            ls -la "/build/'"$TARBALL_NAME"'" "/build/'"$TARBALL_NAME"'.manifest.json"
        '
elif [ "$BOARD_POST_IMAGE" = native-sd ]; then
    echo "--- Phase 7: collecting exact native SD image for $PRODUCER_BOARD ---"
    docker run --rm -v "${VOLUME_NAME}:/build" -e ARTIFACT="$TARBALL_NAME" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -eu
            for suffix in "" .manifest.json .runtime-image.json .runtime-image.sig; do
                source="/build/DCENT_OS_Antminer/buildroot/output/images/${ARTIFACT}${suffix}"
                [ -f "$source" ] && [ ! -L "$source" ] || {
                    echo "ERROR: incomplete native producer output: $source" >&2; exit 1;
                }
                cp "$source" "/build/${ARTIFACT}${suffix}"
            done
            cp /build/DCENT_OS_Antminer/buildroot/output/images/TESTER_README.txt /build/TESTER_README.txt
        '
elif [ "$BOARD_POST_IMAGE" = "board-script" ]; then
    # am2-s19jpro / AM3 Amlogic / am3-bb: the board's post-image.sh already produced
    # the tarball inside the Buildroot output/images dir. Copy it to /build/
    # so Phase 8 can extract it to Windows uniformly.
    echo "--- Phase 7: collecting $TARGET tarball from Buildroot output ---"
    docker run --rm \
        -v "${VOLUME_NAME}:/build" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            SRC="/build/DCENT_OS_Antminer/buildroot/output/images/'"$TARBALL_NAME"'"
            if [ ! -f "$SRC" ]; then
                echo "ERROR: expected tarball not produced by post-image.sh: $SRC" >&2
                ls -la /build/DCENT_OS_Antminer/buildroot/output/images/ >&2 || true
                exit 1
            fi
            cp "$SRC" "/build/'"$TARBALL_NAME"'"
            ls -la "/build/'"$TARBALL_NAME"'"
        '
else
    # Default s9 path: use package_sysupgrade.sh with --board am1-s9
    echo "--- Phase 7: package_sysupgrade.sh (board=$BOARD_PKG_NAME) ---"
    docker run --rm \
        -e DCENT_ALLOW_UNSIGNED_SYSUPGRADE="$DCENT_ALLOW_UNSIGNED_SYSUPGRADE" \
        -e DCENT_PACKAGE_STATUS="$DCENT_PACKAGE_STATUS" \
        -e DCENT_RELEASE_IMAGE="${DCENT_RELEASE_IMAGE:-0}" \
        -e DCENT_RELEASE_CHANNEL="${DCENT_RELEASE_CHANNEL:-beta}" \
        -e DCENT_RELEASE_HARDWARE_RECIPE="${DCENT_RELEASE_HARDWARE_RECIPE:-board-default}" \
        -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        -e DCENT_SOURCE_COMMIT="$DCENT_SOURCE_COMMIT" \
        -e DCENT_SOURCE_COMMIT_EPOCH="$DCENT_SOURCE_COMMIT_EPOCH" \
        -e DCENT_SOURCE_TREE_STATE="$DCENT_SOURCE_TREE_STATE" \
        -e DCENT_BUILD_TARGET="$DCENT_BUILD_TARGET" \
        -e DCENT_BUILD_ARCH="$DCENT_BUILD_ARCH" \
        -e DCENT_TOOLCHAIN_ID="$DCENT_TOOLCHAIN_ID" \
        -e DCENT_REQUIRE_RELEASE_PROVENANCE="$DCENT_REQUIRE_RELEASE_PROVENANCE" \
        -e DCENT_RELEASE_CAPSULE_MODE="$DCENT_RELEASE_CAPSULE_MODE" \
        -e DCENT_CAPSULE_PROVENANCE_VERIFIED="$DCENT_CAPSULE_PROVENANCE_VERIFIED" \
        -e DCENT_PROVENANCE_SOURCE_SNAPSHOT="/dcentos-source-snapshot-release/snapshot.json" \
        -e DCENT_PROVENANCE_GIT_OBJECT_REPO="/dcent-git-object-repo" \
        -e DCENT_PROVENANCE_HELPER="/build/DCENT_OS_Antminer/scripts/source_snapshot.py" \
        -e DCENT_EXTRACTIONS_DIR="/dcent-inputs/files/knowledge-base/extractions/s9" \
        -e DCENT_RELEASE_SIGNING_KEY="$CONTAINER_RELEASE_SIGNING_KEY" \
        -e DCENT_RELEASE_PUBKEY_FILE="$CONTAINER_RELEASE_PUBKEY_FILE" \
        -e DCENT_REQUIRE_RELEASE_KEY="${DCENT_REQUIRE_RELEASE_KEY:-0}" \
        -e BOARD_PKG_NAME="$BOARD_PKG_NAME" \
        "${SIGNING_MOUNT_ARGS[@]}" \
        "${BUILD_INPUT_MOUNT_ARGS[@]}" \
        "${CAPSULE_PROVENANCE_MOUNT_ARGS[@]}" \
        -v "${VOLUME_NAME}:/build" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            cd /build/DCENT_OS_Antminer
            bash scripts/package_sysupgrade.sh \
                --board "$BOARD_PKG_NAME" \
                --output "/build/'"$TARBALL_NAME"'"
        '
fi

# The S9 and AM2 S19j Pro post-image hooks emit the bounded
# final-rootfs ownership ledger while Buildroot's finalized TARGET_DIR and
# package .files-list.txt evidence are still available. Collect it beside the
# release artifact; absence is a pipeline failure for these integrated lanes.
ROOTFS_OWNERSHIP_LEDGER_PATH=""
case "$TARGET" in
    s9|am2-s19jpro)
        ROOTFS_OWNERSHIP_LEDGER_NAME="${TARBALL_NAME}.rootfs-ownership.json"
        docker run --rm \
            -v "${VOLUME_NAME}:/build" \
            "$BUILD_CONTAINER_ID" bash -c '
                set -e
                SRC=/build/DCENT_OS_Antminer/buildroot/output/images/rootfs-ownership.json
                DST=/build/'"$ROOTFS_OWNERSHIP_LEDGER_NAME"'
                [ -f "$SRC" ] || {
                    echo "ERROR: integrated final-rootfs ownership ledger missing: $SRC" >&2
                    exit 1
                }
                cp "$SRC" "$DST"
            '
        ;;
    *)
        ROOTFS_OWNERSHIP_LEDGER_NAME=""
        ;;
esac
echo ""

# -------- Phase 8: extract tarball back to Windows --------
echo "--- Phase 8: extract tarball to $OUTPUT_DIR ---"
docker run --rm \
    -e DCENT_ALLOW_UNSIGNED_SYSUPGRADE="$DCENT_ALLOW_UNSIGNED_SYSUPGRADE" \
    -e DCENT_PACKAGE_STATUS="$DCENT_PACKAGE_STATUS" \
    -e DCENT_RELEASE_PUBKEY_FILE="$CONTAINER_RELEASE_PUBKEY_FILE" \
    -e DCENT_REQUIRE_RELEASE_KEY="${DCENT_REQUIRE_RELEASE_KEY:-0}" \
    -e BOARD_POST_IMAGE="$BOARD_POST_IMAGE" \
    -e ROOTFS_OWNERSHIP_LEDGER_NAME="$ROOTFS_OWNERSHIP_LEDGER_NAME" \
    "${PUBKEY_MOUNT_ARGS[@]}" \
    -v "${VOLUME_NAME}:/build" \
    -v "${POSIX_OUTPUT_DIR}:/out" \
    "$BUILD_CONTAINER_ID" bash -c '
        set -e
        cp /build/'"$TARBALL_NAME"' /out/
        if [ -n "$ROOTFS_OWNERSHIP_LEDGER_NAME" ]; then
            cp "/build/$ROOTFS_OWNERSHIP_LEDGER_NAME" /out/
        fi
        ls -la /out/'"$TARBALL_NAME"'
        echo ""
        echo "SHA256:"
        sha256sum /out/'"$TARBALL_NAME"'
        echo ""
        if [ "$BOARD_POST_IMAGE" = native-sd ]; then
            for suffix in .manifest.json .runtime-image.json .runtime-image.sig; do
                cp /build/'"$TARBALL_NAME"'"$suffix" /out/
            done
            cp /build/TESTER_README.txt /out/TESTER_README.txt
        elif [ "$BOARD_POST_IMAGE" = "vnish-bootbin-sd" ]; then
            echo "VNish boot.bin SD image (no tar listing — this is a raw .img):"
            if [ -f /build/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json ]; then
                cp /build/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json /out/
                echo "Manifest:"
                cat /out/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json
            fi
        elif [ "$BOARD_POST_IMAGE" = "am2-sd-disk" ]; then
            echo "am2 S19j Pro SD disk image (no tar listing — this is a raw .img):"
            if [ ! -f /build/'"$TARBALL_NAME"'.manifest.json ]; then
                echo "ERROR: missing am2 SD completeness manifest: /build/'"$TARBALL_NAME"'.manifest.json" >&2
                exit 1
            fi
            cp /build/'"$TARBALL_NAME"'.manifest.json /out/
            echo "Manifest:"
            cat /out/'"$TARBALL_NAME"'.manifest.json
        else
            echo "Contents:"
            tar tf /out/'"$TARBALL_NAME"' | head -20
        fi
        if [ "$BOARD_POST_IMAGE" != native-sd ]; then
        case "'"$TARGET"'" in
            am2-s17pro|am2-s17plus|am2-t17|am2-t17plus)
            echo ""
            echo "Package-only non-installable validation:"
            cd /build/DCENT_OS_Antminer
            PACKAGE_ONLY_TMP="$(mktemp -d)"
            trap "rm -rf -- \"$PACKAGE_ONLY_TMP\"" EXIT HUP INT TERM
            # shellcheck source=/dev/null
            . ./scripts/lib/sysupgrade_archive_admission.sh
            dcent_sysupgrade_archive_admit \
                /out/'"$TARBALL_NAME"' '"$BOARD_PKG_NAME"' "$PACKAGE_ONLY_TMP"
            tar xf /out/'"$TARBALL_NAME"' -C "$PACKAGE_ONLY_TMP"
            MANIFEST="$PACKAGE_ONLY_TMP/sysupgrade-'"$BOARD_PKG_NAME"'/MANIFEST.json"
            python3 ./scripts/lib/sysupgrade_manifest_json.py validate "$MANIFEST"
            python3 - "$PACKAGE_ONLY_TMP" "$MANIFEST" <<PY
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="ascii"))
if manifest.get("board_target") != "'"$BOARD_PKG_NAME"'":
    raise SystemExit("S17 package-only manifest has the wrong board target")
if manifest.get("installable") is not False:
    raise SystemExit("S17 package-only manifest must declare installable=false")
toolbox = manifest.get("toolbox")
if not isinstance(toolbox, dict) or toolbox.get("install_mode") != "package_only_denied":
    raise SystemExit("S17 package-only manifest must retain package_only_denied")
if toolbox.get("install_command") is not None or toolbox.get("update_command") is not None:
    raise SystemExit("S17 package-only manifest must not advertise Toolbox commands")
for kind in ("kernel", "rootfs", "metadata"):
    payload = manifest["payloads"][kind]
    path = root / payload["path"]
    raw = path.read_bytes()
    if len(raw) != payload["size"] or hashlib.sha256(raw).hexdigest() != payload["sha256"]:
        raise SystemExit(f"S17 package-only {kind} payload binding mismatch")
PY
            python3 ./scripts/extract_am2_s17_kernel.py verify-fit \
                --fit "$PACKAGE_ONLY_TMP/sysupgrade-'"$BOARD_PKG_NAME"'/kernel" >/dev/null
            rm -rf -- "$PACKAGE_ONLY_TMP"
            trap - EXIT HUP INT TERM
            ;;
            # Added by Phase 4B: am3-s19jpro-aml + am3-t21 share structural
            # tarball validation. The typed manifest helper separately admits
            # T21 only as package_only_denied; it receives no flash geometry.
            s9|am3-s19kpro|am3-s19kpro-nopic|am3-s19xp|am3-s19jxp|am3-s19jproa|am3-s19jproplus|am3-s21|am3-s21pro|am3-s21xp|am3-s19jpro-aml|am3-t21|am2-s19jpro|am2-s19pro)
            # End Phase 4B
            # DevOps Q1 finding 4I (2026-05-15): wire pre_flash_validate.sh
            # --package-only for am2-s19jpro so the AM2 signing flow mirrors
            # the AM3 signing flow that was wired in W11.
            echo ""
            echo "Package-only validation:"
            cd /build/DCENT_OS_Antminer
            DCENT_ALLOW_UNSIGNED_SYSUPGRADE="${DCENT_ALLOW_UNSIGNED_SYSUPGRADE:-0}" \
            DCENT_PACKAGE_STATUS="${DCENT_PACKAGE_STATUS:-release}" \
                ./scripts/pre_flash_validate.sh --package-only /out/'"$TARBALL_NAME"' "'"$BOARD_PKG_NAME"'"
            ;;
            am3-bb|am3-bb-s19jpro|am3-bb-s19jpro-payload)
            echo ""
            echo "SD-card payload validation:"
            case "'"$TARGET"'" in
                am3-bb) SD_PREFIX="dcentos-am3-bb-sdcard" ;;
                am3-bb-s19jpro|am3-bb-s19jpro-payload) SD_PREFIX="dcentos-am3-bb-s19jpro-sdcard" ;;
            esac
            PAYLOAD_ADMIT_DIR="$(mktemp -d)"
            trap "rm -rf -- \"$PAYLOAD_ADMIT_DIR\"" EXIT HUP INT TERM
            cd /build/DCENT_OS_Antminer
            python3 ./scripts/safe_extract_am3_bb_payload.py \
                /out/'"$TARBALL_NAME"' "$PAYLOAD_ADMIT_DIR" \
                --expected-target "'"$BOARD_PKG_NAME"'"
            PAYLOAD_ROOT="$PAYLOAD_ADMIT_DIR/$SD_PREFIX"
            CPIO_LIST="$(gzip -dc "$PAYLOAD_ROOT/uramdisk.image.gz" | cpio -it --quiet | sed "s#^\./##")"
            if printf "%s\n" "$CPIO_LIST" \
                | grep -E "(^|/)(uart_trans\.ko|monitor-ipsig|S65monitor-ipsig|daemons|daemonc|update-daemon|S67update-daemon|updateporc\.sh)$"; then
                echo "ERROR: forbidden stock BB daemon/blob present"
                exit 1
            fi
            if [ "'"$BOARD_PKG_NAME"'" = "am3-bb-s19jpro" ]; then
                printf "%s\n" "$CPIO_LIST" | grep -qx "etc/dcentos/board_target"
                printf "%s\n" "$CPIO_LIST" | grep -qx "etc/dcentos/board_targets/am3-bb-s19jpro.toml"
                printf "%s\n" "$CPIO_LIST" | grep -qx "etc/init.d/S50dropbear"
                printf "%s\n" "$CPIO_LIST" | grep -qx "etc/init.d/S81mcp"
                printf "%s\n" "$CPIO_LIST" | grep -qx "etc/init.d/S82dcentrald"
            fi
            ROOTFS_CHECK_DIR="/tmp/${SD_PREFIX}-rootfs-check"
            rm -rf "$ROOTFS_CHECK_DIR"
            mkdir -p "$ROOTFS_CHECK_DIR"
            ( cd "$ROOTFS_CHECK_DIR" && gzip -dc "$PAYLOAD_ROOT/uramdisk.image.gz" | cpio -idmu --quiet )
            check_armv7_elf() {
                rel="$1"
                path="$ROOTFS_CHECK_DIR/$rel"
                if [ ! -e "$path" ]; then
                    echo "ERROR: missing $rel in AM3-BB rootfs" >&2
                    exit 1
                fi
                desc="$(file -Lb "$path" 2>/dev/null || true)"
                case "$desc" in
                    *"ELF 32-bit LSB"*ARM*EABI5*) return 0 ;;
                esac
                echo "ERROR: $rel must be ARMv7/EABI5 ELF; got: ${desc:-unknown file type}" >&2
                exit 1
            }
            check_armv7_elf "bin/busybox"
            check_armv7_elf "sbin/init"
            check_armv7_elf "usr/sbin/dropbear"
            check_armv7_elf "usr/local/bin/dcentrald"
            check_armv7_elf "usr/local/bin/dcentos-discovery"
            BAD_ELF="$(find "$ROOTFS_CHECK_DIR" -type f -exec file {} + | grep -E "ELF 64-bit|aarch64|x86-64" || true)"
            if [ -n "$BAD_ELF" ]; then
                echo "ERROR: AM3-BB rootfs contains non-ARMv7 ELF payloads" >&2
                printf "%s\n" "$BAD_ELF" >&2
                exit 1
            fi
            rm -rf "$ROOTFS_CHECK_DIR"
            rm -rf -- "$PAYLOAD_ADMIT_DIR"
            trap - EXIT HUP INT TERM
            echo "PASS: exact target-bound SD package admitted; no forbidden stock BB daemon/blob paths; required management files and ARMv7 critical binaries verified"
            ;;
        esac
        fi
    '
echo ""

FINAL_BANNER_STATUS="success"
if [ "$BOARD_POST_IMAGE" = "vnish-bootbin-sd" ] && \
   [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
    echo "ERROR: VNish prototype cannot enter the release-signing lane while" >&2
    echo "       vendor_blob_unaudited=true and its RSA verification gate is OPEN" >&2
    exit 1
fi
if [ "$BOARD_POST_IMAGE" = "am2-sd-disk" ]; then
    AM2_SD_MANIFEST="$OUTPUT_DIR/$TARBALL_NAME.manifest.json"
    if [ ! -f "$AM2_SD_MANIFEST" ]; then
        echo "ERROR: missing am2 SD completeness manifest after extraction: $AM2_SD_MANIFEST" >&2
        exit 1
    fi
    if ! dcent_sd_require_complete_manifest_for_signing \
        "$OUTPUT_DIR/$TARBALL_NAME" "$AM2_SD_MANIFEST" >/dev/null 2>&1; then
        if [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
            RENAMED_AM2_IMAGE=$(dcent_sd_mark_incomplete_lab_image "$OUTPUT_DIR/$TARBALL_NAME" "$AM2_SD_MANIFEST")
            TARBALL_NAME="$(basename "$RENAMED_AM2_IMAGE")"
            echo "NOTICE: am2 SD image is incomplete; relabelled to $TARBALL_NAME before signing refusal"
            dcent_sd_require_complete_manifest_for_signing \
                "$OUTPUT_DIR/$TARBALL_NAME" \
                "$OUTPUT_DIR/$TARBALL_NAME.manifest.json"
        elif is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then
            # Applies the -UNSIGNED-LAB-ROOTFS-ONLY.img suffix for incomplete
            # AM2 images so a rootfs-only staging artifact cannot look signed.
            RENAMED_AM2_IMAGE=$(dcent_sd_mark_incomplete_lab_image "$OUTPUT_DIR/$TARBALL_NAME" "$AM2_SD_MANIFEST")
            TARBALL_NAME="$(basename "$RENAMED_AM2_IMAGE")"
            FINAL_BANNER_STATUS="unsigned_lab_rootfs_only"
            echo "NOTICE: am2 SD image is incomplete and unsigned; relabelled to $TARBALL_NAME"
        else
            echo "ERROR: incomplete am2 SD image requires release signing proof or explicit lab unsigned mode" >&2
            exit 1
        fi
    fi
fi

if [ -n "$ROOTFS_OWNERSHIP_LEDGER_NAME" ]; then
    ROOTFS_OWNERSHIP_LEDGER_PATH="$OUTPUT_DIR/$ROOTFS_OWNERSHIP_LEDGER_NAME"
    [ -f "$ROOTFS_OWNERSHIP_LEDGER_PATH" ] || {
        echo "ERROR: final-rootfs ownership ledger was not extracted: $ROOTFS_OWNERSHIP_LEDGER_PATH" >&2
        exit 1
    }
    echo "Final-rootfs ownership ledger: $ROOTFS_OWNERSHIP_LEDGER_PATH"
fi

# Retain the exact Phase-0 export bytes that Phase 5 consumed. These flat,
# release-scoped pairs are semantic inputs to source-closure v4. They remain
# snapshot-consistency evidence only: compiler causality, build execution, and
# equivalence to the installed payload are deliberately not claimed.
if [ "$TOOLCHAIN_SHA256_MANDATORY" = "1" ]; then
    # 995183dee renamed the remove-helper to a require-absent admission but
    # missed this retention-site call; the orphaned name killed the first
    # producer run to ever reach the post-validation retention block
    # (drop1-20260916-uh8_s8i6). Fail closed on stale sidecars here too.
    dcent_require_prebuilt_rust_sidecars_absent "$TARBALL_NAME"
    python3 "$SCRIPT_DIR/binary_build_receipt.py" \
        retain-export-snapshot-set \
        --stage "$BINARY_EXPORT_STAGE" \
        --output-dir "$OUTPUT_DIR" \
        --artifact-prefix "$TARBALL_NAME" >/dev/null
    for binary_name in $(dcent_required_prebuilt_binaries); do
        retained_binary="$OUTPUT_DIR/${TARBALL_NAME}.prebuilt-rust.${binary_name}.bin"
        retained_receipt="$OUTPUT_DIR/${TARBALL_NAME}.prebuilt-rust.${binary_name}.build-receipt.json"
        [ -f "$retained_binary" ] && [ ! -L "$retained_binary" ] || {
            echo "ERROR: retained prebuilt Rust binary is missing or a symlink: $retained_binary" >&2
            exit 1
        }
        [ -f "$retained_receipt" ] && [ ! -L "$retained_receipt" ] || {
            echo "ERROR: retained prebuilt Rust receipt is missing or a symlink: $retained_receipt" >&2
            exit 1
        }
        PREBUILT_RUST_INPUT_ARGS+=(
            --prebuilt-rust-input "$binary_name" "$retained_binary" "$retained_receipt"
        )
        PREBUILT_RUST_INPUT_COUNT=$((PREBUILT_RUST_INPUT_COUNT + 1))
    done
fi

# -------- Phase 8: deterministic partial source-closure receipt --------
# This binds the exact declared source/build definitions and produced artifact
# bytes. It explicitly records that kernel/rootfs byte reproducibility and
# Buildroot legal-info completeness/correctness remain unproven.
SOURCE_CLOSURE_PATH=""
SOURCE_CLOSURE_SIGNATURE_PATH=""
BUILDROOT_LEGAL_INVENTORY_PATH=""
if [ "$TOOLCHAIN_SHA256_MANDATORY" = "1" ]; then
    BUILDROOT_LEGAL_INVENTORY_PATH="$OUTPUT_DIR/${TARBALL_NAME}.buildroot-legal.json"
    docker run --rm \
        -e TARGET="$TARGET" \
        -e BUILD_ARCH="$BUILD_ARCH" \
        -e BUILDROOT_REPOSITORY="$BUILDROOT_REPOSITORY" \
        -e BUILDROOT_COMMIT="$BUILDROOT_COMMIT" \
        -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        -e ARTIFACT_NAME="$TARBALL_NAME" \
        -v "${VOLUME_NAME}:/build" \
        -v "${POSIX_PROJECT_DIR}:/project:ro" \
        -v "${POSIX_OUTPUT_DIR}:/out" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            INVENTORY="/out/${ARTIFACT_NAME}.buildroot-legal.json"
            python3 /project/scripts/buildroot_legal_inventory.py generate \
                --legal-info-dir /build/DCENT_OS_Antminer/buildroot/output/legal-info \
                --buildroot-repository "$BUILDROOT_REPOSITORY" \
                --buildroot-commit "$BUILDROOT_COMMIT" \
                --target "$TARGET" \
                --arch "$BUILD_ARCH" \
                --artifact "/out/$ARTIFACT_NAME" \
                --source-date-epoch "$SOURCE_DATE_EPOCH" \
                --output "$INVENTORY" >/dev/null
            python3 /project/scripts/buildroot_legal_inventory.py verify \
                --artifact-dir /out \
                --legal-info-dir /build/DCENT_OS_Antminer/buildroot/output/legal-info \
                "$INVENTORY" >/dev/null
        '
    [ -f "$BUILDROOT_LEGAL_INVENTORY_PATH" ] || {
        echo "ERROR: Buildroot legal-info inventory was not emitted" >&2
        exit 1
    }
    echo "Buildroot legal-info inventory: $BUILDROOT_LEGAL_INVENTORY_PATH"

    RUST_INVENTORY_PATH="$OUTPUT_DIR/${TARBALL_NAME}.rust-dependencies.json"
    python3 "$SCRIPT_DIR/rust_dependency_inventory.py" generate \
        --workspace "$PROJECT_DIR/dcentrald" \
        --source-root "$REPO_ROOT" \
        --metadata-json "$RUST_METADATA_FILE" \
        --metadata-path-map "/src=$PROJECT_DIR/dcentrald" \
        --metadata-path-map "/dcent-schema=$REPO_ROOT/projects/dcent-schema" \
        --target "$BUILD_ARCH" \
        --artifact "$OUTPUT_DIR/$TARBALL_NAME" \
        --source-date-epoch "$SOURCE_DATE_EPOCH" \
        --output "$RUST_INVENTORY_PATH" >/dev/null
    python3 "$SCRIPT_DIR/rust_dependency_inventory.py" verify \
        --workspace "$PROJECT_DIR/dcentrald" \
        --source-root "$REPO_ROOT" \
        --metadata-json "$RUST_METADATA_FILE" \
        --metadata-path-map "/src=$PROJECT_DIR/dcentrald" \
        --metadata-path-map "/dcent-schema=$REPO_ROOT/projects/dcent-schema" \
        --artifact-dir "$OUTPUT_DIR" \
        "$RUST_INVENTORY_PATH" >/dev/null
    echo "Rust dependency inventory: $RUST_INVENTORY_PATH"

    SOURCE_CLOSURE_PATH="$OUTPUT_DIR/${TARBALL_NAME}.source-closure.json"
    SOURCE_CLOSURE_CONFIG_ARGS=()
    for SOURCE_CLOSURE_FRAGMENT in $BR_DEFCONFIG_FRAGMENTS; do
        SOURCE_CLOSURE_CONFIG_ARGS+=(
            --buildroot-config "$PROJECT_DIR/br2_external_dcentos/configs/$SOURCE_CLOSURE_FRAGMENT"
        )
    done
    SOURCE_CLOSURE_CONFIG_ARGS+=(
        --buildroot-config "$PROJECT_DIR/br2_external_dcentos/configs/$BR_DEFCONFIG"
    )
    SOURCE_CLOSURE_ARTIFACT_ARGS=(
        --artifact "$OUTPUT_DIR/$TARBALL_NAME"
        --artifact "$BUILDROOT_LEGAL_INVENTORY_PATH"
        --artifact "$RUST_INVENTORY_PATH"
    )
    if [ -n "$ROOTFS_OWNERSHIP_LEDGER_PATH" ]; then
        SOURCE_CLOSURE_ARTIFACT_ARGS+=(--artifact "$ROOTFS_OWNERSHIP_LEDGER_PATH")
    fi
    python3 "$SCRIPT_DIR/source_closure.py" generate \
        --repo-root "$GIT_OBJECT_REPO" \
        --source-commit "$DCENT_SOURCE_COMMIT" \
        --source-snapshot "$CAPSULE_SOURCE_SNAPSHOT" \
        --release-invocation "$CAPSULE_INVOCATION_STAGE" \
        --source-date-epoch "$SOURCE_DATE_EPOCH" \
        --target "$TARGET" \
        --arch "$BUILD_ARCH" \
        --cargo-lock "$PROJECT_DIR/dcentrald/Cargo.lock" \
        --cargo-build-script "$SCRIPT_DIR/build-dcentrald.sh" \
        --buildroot-repository "$BUILDROOT_REPOSITORY" \
        --buildroot-commit "$BUILDROOT_COMMIT" \
        "${SOURCE_CLOSURE_CONFIG_ARGS[@]}" \
        --external-tree "$PROJECT_DIR/br2_external_dcentos" \
        --toolchain-id "$DCENT_TOOLCHAIN_ID" \
        --toolchain-sha256 "$TOOLCHAIN_SHA256" \
        --toolchain-verified \
        --container-image-id "$BUILD_CONTAINER_ID" \
        --container-definition "$PROJECT_DIR/Dockerfile.build" \
        --build-input-snapshot "$BUILD_INPUT_SNAPSHOT" \
        "${PREBUILT_RUST_INPUT_ARGS[@]}" \
        "${SOURCE_CLOSURE_ARTIFACT_ARGS[@]}" \
        --receipt-authentication detached_ed25519_required_for_release \
        --output "$SOURCE_CLOSURE_PATH" >/dev/null
    # Authenticate the canonical receipt that binds the firmware artifact,
    # Rust inventory, and (for integrated targets) rootfs ownership ledger.
    # This does not widen the receipt's deliberately partial claim scope.
    [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ] || {
        echo "ERROR: release source closure requires DCENT_RELEASE_SIGNING_KEY" >&2
        exit 1
    }
    [ -n "${DCENT_RELEASE_PUBKEY_FILE:-}" ] || {
        echo "ERROR: release source closure requires a pinned DCENT_RELEASE_PUBKEY_FILE" >&2
        exit 1
    }
    SOURCE_CLOSURE_SIGNATURE_PATH="${SOURCE_CLOSURE_PATH}.sig"
    # Sign with the 0600 invocation-volume copy (CONTAINER_RELEASE_SIGNING_KEY,
    # staged before Phase 6). The raw bind mount reads 0777 inside the
    # container and the receipt signer's private-key mode guard refuses it.
    docker run --rm \
        -v "${POSIX_OUTPUT_DIR}:/out" \
        -v "${POSIX_PROJECT_DIR}:/project:ro" \
        -v "${VOLUME_NAME}:/build:ro" \
        "${PUBKEY_MOUNT_ARGS[@]}" \
        -e RECEIPT_NAME="$(basename "$SOURCE_CLOSURE_PATH")" \
        -e RELEASE_SIGNING_KEY="${CONTAINER_RELEASE_SIGNING_KEY}" \
        "$BUILD_CONTAINER_ID" bash -c '
            set -e
            bash /project/scripts/sign_release_receipt.sh \
                "/out/$RECEIPT_NAME" \
                "$RELEASE_SIGNING_KEY" \
                /dcent-release-ed25519.pub \
                "/out/$RECEIPT_NAME.sig"
        '
    [ -f "$SOURCE_CLOSURE_SIGNATURE_PATH" ] || {
        echo "ERROR: signed source-closure receipt was not emitted" >&2
        exit 1
    }
    [ "$(wc -c < "$SOURCE_CLOSURE_SIGNATURE_PATH" | tr -d '[:space:]')" = "64" ] || {
        echo "ERROR: Ed25519 source-closure signature must be exactly 64 bytes" >&2
        exit 1
    }
    python3 "$SCRIPT_DIR/source_closure.py" verify \
        --repo-root "$GIT_OBJECT_REPO" \
        --artifact-dir "$OUTPUT_DIR" \
        --source-snapshot "$CAPSULE_SOURCE_SNAPSHOT" \
        --release-invocation "$CAPSULE_INVOCATION_STAGE" \
        --build-input-snapshot "$BUILD_INPUT_SNAPSHOT" \
        --signature "$SOURCE_CLOSURE_SIGNATURE_PATH" \
        --public-key "$DCENT_RELEASE_PUBKEY_FILE" \
        "$SOURCE_CLOSURE_PATH" >/dev/null
    # Retain only the canonical path/hash/ID descriptor. The restricted input
    # bytes remain private and the live snapshot is still required above for
    # release admission; this copy is post-cleanup audit evidence only.
    python3 "$SCRIPT_DIR/release_publication.py" copy \
        --source "$BUILD_INPUT_SNAPSHOT" \
        --output "$OUTPUT_DIR/release-packaging-input.json" >/dev/null
    echo "Source closure: $SOURCE_CLOSURE_PATH"
    echo "Source closure signature: $SOURCE_CLOSURE_SIGNATURE_PATH"
else
    RUST_INVENTORY_PATH=""
    echo "Rust dependency inventory: skipped for non-release lab build"
    echo "Source closure: skipped for non-release lab build with advisory toolchain integrity"
fi

# -------- Phase 8a: standardized release name (operator directive 2026-06-14) --------
# Auto-name the compiled artifact per the canonical DCENT_OS convention
# (DCENTOS_<BOARD><GEN>_<MODEL>_<channel><YYYYMMDD>) via the single-source-of-truth
# helper, so released images are named consistently with no hand-typed names.
# ADDITIVE: the legacy "$TARBALL_NAME" artifact is unchanged; this records the
# standardized name + firmware version + SHA256 next to it and drops a same-named copy.
# Channel override: DCENT_RELEASE_CHANNEL (default beta). See
#  + scripts/firmware_release_name.sh.
if [ -n "$RELEASE_NAME" ]; then
    RELEASE_ARTIFACT_SRC="$OUTPUT_DIR/$TARBALL_NAME"
    if [ -f "$RELEASE_ARTIFACT_SRC" ]; then
        FW_VERSION="$(awk -F'"' '/^version = /{print $2; exit}' "$PROJECT_DIR/dcentrald/Cargo.toml" 2>/dev/null || echo unknown)"
        # CE-341: a canonical alias like DCENTOS_XIL1_S9_beta<date>.tar must NOT
        # be emitted for a lab/unsigned build — that would let an unsigned lab
        # artifact carry the exact published beta stem + a release-looking
        # sidecar at the publish step (the internal MANIFEST.json is honest, but
        # this EXTERNAL alias/sidecar was not). Compute release-grade from the
        # same signing/status gates the build already honored; a non-release-grade
        # build gets a loud LAB-UNSIGNED-NOT-FOR-RELEASE marker baked into the
        # alias so it can never masquerade as the clean beta artifact. Stricter-
        # only: the honest internal MANIFEST.json + legacy "$TARBALL_NAME" are
        # untouched. firmware_release_name.sh only accepts beta|dev|rc|stable
        # channels, so the label is a filename suffix, not a lab channel token.
        RELEASE_GRADE=1
        is_release_status "$DCENT_PACKAGE_STATUS" || RELEASE_GRADE=0
        if is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then RELEASE_GRADE=0; fi
        is_truthy "${DCENT_RELEASE_IMAGE:-0}" || RELEASE_GRADE=0
        [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ] || RELEASE_GRADE=0
        if [ "$RELEASE_GRADE" = "1" ]; then
            SIGNATURE_TRUST="signed"
            PROOF_SCOPE="release_grade"
            RELEASE_COPY="$RELEASE_GRADE_PATH"
        else
            SIGNATURE_TRUST="unsigned"
            PROOF_SCOPE="lab_local"
            RELEASE_COPY="$RELEASE_LAB_PATH"
        fi
        RELEASE_EXPECTED_SHA_ARGS=()
        if [ -n "$SOURCE_CLOSURE_PATH" ]; then
            RELEASE_CLOSURE_SHA="$(
                python3 "$SCRIPT_DIR/source_closure.py" query-artifact \
                    --manifest "$SOURCE_CLOSURE_PATH" \
                    --path "$TARBALL_NAME" \
                    --field sha256
            )"
            RELEASE_EXPECTED_SHA_ARGS=(--expected-sha256 "$RELEASE_CLOSURE_SHA")
        fi
        RELEASE_PUBLICATION_RESULT="$(python3 "$SCRIPT_DIR/release_publication.py" copy \
            --source "$RELEASE_ARTIFACT_SRC" \
            --output "$RELEASE_COPY" \
            "${RELEASE_EXPECTED_SHA_ARGS[@]}")"
        RELEASE_SHA="$(
            printf '%s\n' "$RELEASE_PUBLICATION_RESULT" \
                | python3 "$SCRIPT_DIR/release_publication.py" query-result --field sha256
        )"
        RELEASE_METADATA_CONTENT="$({
            echo "release_name=$RELEASE_NAME"
            echo "firmware_version=$FW_VERSION"
            echo "build_target=$TARGET"
            echo "channel=${DCENT_RELEASE_CHANNEL:-beta}"
            echo "artifact=$(basename "$RELEASE_COPY")"
            echo "legacy_artifact=$TARBALL_NAME"
            echo "sha256=$RELEASE_SHA"
            echo "package_status=$DCENT_PACKAGE_STATUS"
            echo "allow_unsigned=$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"
            echo "release_image=${DCENT_RELEASE_IMAGE:-0}"
            echo "created_at_utc=$DCENT_CREATED_AT_UTC"
            echo "source_date_epoch=$SOURCE_DATE_EPOCH"
            echo "source_commit=$DCENT_SOURCE_COMMIT"
            echo "source_tree_state=$DCENT_SOURCE_TREE_STATE"
            echo "release_invocation_id=$CAPSULE_INVOCATION_ID"
            echo "source_snapshot_id=$CAPSULE_SOURCE_ID"
            echo "source_snapshot_descriptor_sha256=$CAPSULE_SOURCE_DESCRIPTOR_SHA256"
            echo "publication_model=private_exact_set_pending_atomic_directory_promotion"
            echo "build_arch=$DCENT_BUILD_ARCH"
            echo "toolchain_id=$DCENT_TOOLCHAIN_ID"
            if [ -n "$SOURCE_CLOSURE_PATH" ]; then
                echo "source_closure=$(basename "$SOURCE_CLOSURE_PATH")"
                echo "source_closure_signature=$(basename "$SOURCE_CLOSURE_SIGNATURE_PATH")"
                echo "prebuilt_rust_inputs=bound_in_signed_source_closure_v4"
                echo "prebuilt_rust_input_count=$PREBUILT_RUST_INPUT_COUNT"
                echo "prebuilt_rust_build_execution_attestation=not_attested"
                echo "prebuilt_rust_installed_payload_equivalence=not_evaluated"
                echo "buildroot_legal_inventory=$(basename "$BUILDROOT_LEGAL_INVENTORY_PATH")"
                echo "rust_dependency_inventory=$(basename "$RUST_INVENTORY_PATH")"
            else
                echo "source_closure=not_emitted_non_release_lab"
                echo "source_closure_signature=not_emitted_non_release_lab"
                echo "prebuilt_rust_inputs=not_retained_non_release_lab"
                echo "prebuilt_rust_input_count=0"
                echo "prebuilt_rust_build_execution_attestation=not_attested"
                echo "prebuilt_rust_installed_payload_equivalence=not_evaluated"
                echo "buildroot_legal_inventory=not_emitted_non_release_lab"
                echo "rust_dependency_inventory=not_emitted_non_release_lab"
            fi
            if [ -n "$ROOTFS_OWNERSHIP_LEDGER_PATH" ]; then
                echo "rootfs_ownership_ledger=$(basename "$ROOTFS_OWNERSHIP_LEDGER_PATH")"
            else
                echo "rootfs_ownership_ledger=not_integrated_for_target"
            fi
            echo "signature_trust=$SIGNATURE_TRUST"
            echo "proof_scope=$PROOF_SCOPE"
            echo "release_grade=$RELEASE_GRADE"
            echo "fund_url=https://d-central.tech/fund/"
        })"
        echo "--- Standardized release name (Phase 8a) ---"
        echo "  name:     $RELEASE_NAME   (firmware $FW_VERSION)"
        echo "  artifact: $RELEASE_COPY"
        echo "  sha256:   $RELEASE_SHA"
        echo "  trust:    signature_trust=$SIGNATURE_TRUST proof_scope=$PROOF_SCOPE release_grade=$RELEASE_GRADE"
        echo "  metadata: $RELEASE_METADATA_PATH (published after signing stages)"
        echo ""
    fi
else
    if dcent_release_provenance_required; then
        echo "ERROR: release build has no canonical publication name for target '$TARGET'" >&2
        exit 1
    fi
    echo "WARN: firmware_release_name.sh produced no name for target '$TARGET'; artifact stays '$TARBALL_NAME' only." >&2
fi

# -------- Phase 8b (am3-bb family): sign the SD-card tarball --------
# W4.5 (2026-05-07): unlike sysupgrade tarballs (whose MANIFEST.json is signed
# inside the archive by the board post-image script), the am3-bb SD-card
# payload is a flat tarball with no inner manifest. Produce a sibling
# `dcentos-am3-bb-sdcard.tar.sig` (raw ed25519 over the .tar bytes) so an
# operator can verify integrity before imaging an SD card.
#
# Skipped for lab/unsigned builds (DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1 with no
# signing key). Required when DCENT_RELEASE_SIGNING_KEY is set.
if [ "$TARGET" = "am3-bb" ] || [ "$TARGET" = "am3-bb-s19jpro" ] || [ "$TARGET" = "am3-bb-s19jpro-payload" ]; then
    if [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
        echo "--- Phase 8b: sign $TARGET SD-card tarball (ed25519) ---"
        # Sign with the 0600 invocation-volume copy (staged before Phase 6);
        # the raw bind mount reads 0777 in-container and the artifact
        # signer's private-key mode guard refuses it. The host-side key
        # existence/transport checks already ran with the mount setup.
        docker run --rm \
            -v "${POSIX_OUTPUT_DIR}:/out" \
            -v "${POSIX_PROJECT_DIR}:/project:ro" \
            -v "${VOLUME_NAME}:/build:ro" \
            "${PUBKEY_MOUNT_ARGS[@]}" \
            -e TARBALL_NAME="$TARBALL_NAME" \
            -e DCENT_RELEASE_PUBKEY_FILE="$CONTAINER_RELEASE_PUBKEY_FILE" \
            -e RELEASE_SIGNING_KEY="${CONTAINER_RELEASE_SIGNING_KEY}" \
            "$BUILD_CONTAINER_ID" bash -c '
                set -e
                python3 /project/scripts/sign_release_artifact.py \
                    "/out/${TARBALL_NAME}" \
                    --key "${RELEASE_SIGNING_KEY}" \
                    --pubkey "${DCENT_RELEASE_PUBKEY_FILE}" \
                    --output-sig "/out/${TARBALL_NAME}.sig"
            '
        if [ "${RELEASE_GRADE:-0}" = "1" ] && [ -n "${RELEASE_COPY:-}" ]; then
            RELEASE_SIGNATURE_PATH="${RELEASE_COPY}.sig"
            python3 "$SCRIPT_DIR/release_publication.py" copy \
                --source "$OUTPUT_DIR/${TARBALL_NAME}.sig" \
                --output "$RELEASE_SIGNATURE_PATH" >/dev/null
            openssl pkeyutl -verify -rawin -pubin \
                -inkey "$DCENT_RELEASE_PUBKEY_FILE" \
                -sigfile "$RELEASE_SIGNATURE_PATH" \
                -in "$RELEASE_COPY" >/dev/null
        fi
    elif is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then
        echo "--- Phase 8b: skipping $TARGET tarball signing (lab/unsigned build) ---"
    fi
fi

# -------- Phase 8c (SD .img variants): sign the raw SD image --------
#  2026-05-15 Phase 4I: eligible SD .img carriers get a
# sibling Ed25519 `<name>.img.sig` next to the image. VNish remains an unsigned
# prototype while its vendor/RSA trust gates are open.
# Uses the same release key as Phase 8b. The sign_sd_image.sh wrapper does
# the openssl invocation; here we just bind-mount the key and invoke it.
# Lab builds without DCENT_RELEASE_SIGNING_KEY must explicitly request the
# unsigned-lab path; that path refuses any stale sibling signature.
if [ "$BOARD_POST_IMAGE" = "vnish-bootbin-sd" ] || [ "$BOARD_POST_IMAGE" = "am2-sd-disk" ]; then
    if [ -n "${DCENT_RELEASE_SIGNING_KEY:-}" ]; then
        echo "--- Phase 8c: sign $TARGET SD .img (ed25519) ---"
        if [ "$BOARD_POST_IMAGE" = "am2-sd-disk" ]; then
            dcent_sd_require_complete_manifest_for_signing \
                "$OUTPUT_DIR/$TARBALL_NAME" \
                "$OUTPUT_DIR/$TARBALL_NAME.manifest.json"
        fi
        # Same 0600 invocation-volume copy as 8b; the raw /signkey bind
        # mount reads 0777 in-container and the signer refuses it.
        docker run --rm \
            -v "${POSIX_OUTPUT_DIR}:/out" \
            -v "${POSIX_PROJECT_DIR}:/project:ro" \
            -v "${VOLUME_NAME}:/build:ro" \
            "${PUBKEY_MOUNT_ARGS[@]}" \
            -e TARBALL_NAME="$TARBALL_NAME" \
            -e DCENT_RELEASE_PUBKEY_FILE="$CONTAINER_RELEASE_PUBKEY_FILE" \
            -e RELEASE_SIGNING_KEY="${CONTAINER_RELEASE_SIGNING_KEY}" \
            "$BUILD_CONTAINER_ID" bash -c '
                set -e
                bash /project/scripts/sign_sd_image.sh "/out/${TARBALL_NAME}" --key "${RELEASE_SIGNING_KEY}"
            '
        if [ "${RELEASE_GRADE:-0}" = "1" ] && [ -n "${RELEASE_COPY:-}" ]; then
            RELEASE_SIGNATURE_PATH="${RELEASE_COPY}.sig"
            python3 "$SCRIPT_DIR/release_publication.py" copy \
                --source "$OUTPUT_DIR/${TARBALL_NAME}.sig" \
                --output "$RELEASE_SIGNATURE_PATH" >/dev/null
            bash "$SCRIPT_DIR/verify_sd_image.sh" "$RELEASE_COPY" \
                --pubkey "$DCENT_RELEASE_PUBKEY_FILE" >/dev/null
        fi
    else
        if is_truthy "$DCENT_ALLOW_UNSIGNED_SYSUPGRADE"; then
            echo "--- Phase 8c: admitting explicit unsigned $TARGET SD .img ---"
        fi
        bash "$SCRIPT_DIR/sign_sd_image.sh" "$OUTPUT_DIR/$TARBALL_NAME" \
            --allow-unsigned-lab
    fi
fi
if [ -n "$PRODUCER" ]; then
    # Verify the runtime embedded in the final artifact before signing these
    # exact primary bytes. Companions are byte copies of its in-image pair.
    python3 "$SCRIPT_DIR/release_runtime_exports.py" export \
        --artifact "$OUTPUT_DIR/$TARBALL_NAME" --board-target "$PRODUCER_BOARD" \
        --channel "${DCENT_RELEASE_CHANNEL:-beta}" --version "$FW_VERSION" \
        --hardware-recipe "${DCENT_RELEASE_HARDWARE_RECIPE:-board-default}" \
        --pubkey "$DCENT_RELEASE_PUBKEY_FILE" >/dev/null
    if [ ! -e "$OUTPUT_DIR/$TARBALL_NAME.sig" ]; then
        python3 "$SCRIPT_DIR/sign_release_artifact.py" "$OUTPUT_DIR/$TARBALL_NAME" \
            --key "$DCENT_RELEASE_SIGNING_KEY" --pubkey "$DCENT_RELEASE_PUBKEY_FILE" \
            --staged-output >/dev/null
    fi
    openssl pkeyutl -verify -rawin -pubin -inkey "$DCENT_RELEASE_PUBKEY_FILE" \
        -sigfile "$OUTPUT_DIR/$TARBALL_NAME.sig" -in "$OUTPUT_DIR/$TARBALL_NAME" >/dev/null
    if [ "$PRODUCER_ARTIFACT_KIND" = native-sd-image ]; then
        python3 "$SCRIPT_DIR/release_producer.py" verify-native-media \
            --producer "$PRODUCER" --artifact "$OUTPUT_DIR/$TARBALL_NAME" \
            --version "$FW_VERSION" --channel "${DCENT_RELEASE_CHANNEL:-beta}" \
            --hardware-recipe "${DCENT_RELEASE_HARDWARE_RECIPE:-board-default}" \
            --pubkey "$DCENT_RELEASE_PUBKEY_FILE" >/dev/null
    fi
    python3 "$SCRIPT_DIR/release_dashboard.py" verify \
        --source "$PROJECT_DIR/dashboard" --output "$CAPSULE_RESULT_ROOT/dashboard"
    python3 "$SCRIPT_DIR/release_publication.py" copy \
        --source "$CAPSULE_RESULT_ROOT/dashboard/dashboard-build.json" \
        --output "$OUTPUT_DIR/${TARBALL_NAME}.dashboard-build.json" >/dev/null
    python3 "$SCRIPT_DIR/release_result_stage.py" verify \
        --invocation-stage "$CAPSULE_INVOCATION_STAGE" "$CAPSULE_RESULT_STAGE" >/dev/null
fi
if [ -n "${RELEASE_METADATA_CONTENT:-}" ]; then
    printf '%s\n' "$RELEASE_METADATA_CONTENT" \
        | python3 "$SCRIPT_DIR/release_publication.py" stdin \
            --output "$RELEASE_METADATA_PATH" >/dev/null
fi
echo ""

echo "==================================================================="
if [ "$FINAL_BANNER_STATUS" = "unsigned_lab_rootfs_only" ]; then
    echo "LAB STAGING ONLY - unsigned rootfs-only SD image ready at:"
else
    echo "SUCCESS - artifact ready at:"
fi
echo "  $OUTPUT_DIR/$TARBALL_NAME"
if [ -f "$OUTPUT_DIR/$TARBALL_NAME.manifest.json" ]; then
    echo "  Manifest: $OUTPUT_DIR/$TARBALL_NAME.manifest.json"
fi
if [ -n "$SOURCE_CLOSURE_PATH" ]; then
    echo "  Source closure: $SOURCE_CLOSURE_PATH"
    echo "  Closure signature: $SOURCE_CLOSURE_SIGNATURE_PATH"
fi
if [ -n "$ROOTFS_OWNERSHIP_LEDGER_PATH" ]; then
    echo "  Rootfs ownership ledger: $ROOTFS_OWNERSHIP_LEDGER_PATH"
fi
if [ -n "$PRODUCER" ]; then
    echo "Verified producer $PRODUCER_BOARD: $OUTPUT_DIR/$TARBALL_NAME"
    exit 0
fi

echo ""
if [ "$TARGET" = "am2-s19jpro" ]; then
    echo "Next (Phase 3 — S19j Pro .139):"
    echo "  scp -O \"$OUTPUT_DIR/$TARBALL_NAME\" root@203.0.113.139:/data/"
    echo "  ssh root@203.0.113.139 'sysupgrade --test /data/$TARBALL_NAME'"
    echo "  DO NOT flash until: (a) am2-s19j kernel extracted, (b) dcentrald config"
    echo "                      finalized by Agent C, (c) inactive UBI slot volume"
    echo "                      counts verified (see feedback_ubi_inactive_slot_volume_mismatch.md)."
elif [ "$TARGET" = "am3-s19xp" ]; then
    echo "Management-only package-format artifact ready for $TARGET:"
    echo "  $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "Runtime staging, native extraction, persistent install, OTA, and recovery are denied."
    echo "The tarball retains exact model/package evidence only; it carries no write geometry."
elif [ "$TARGET" = "am3-s19jxp" ]; then
    echo "Management-only package-format artifact ready for $TARGET:"
    echo "  $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "Runtime staging, native extraction, persistent install, OTA, and recovery are denied."
    echo "The tarball retains exact model/package evidence only; it carries no write geometry."
elif [ "$TARGET" = "am3-s19jproplus" ]; then
    echo "Experimental exact-identity Amlogic artifact ready for $TARGET:"
    echo "  $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "Prepare the native rootfs only after offline package validation:"
    echo "  scripts/build_amlogic_native_install.sh --variant s19jproplus"
    echo "Use dcent amlogic-route with exact observed PCB, lock epoch, geometry,"
    echo "MAC, package, backup, and restore proof. Model-only installation remains denied."
elif [ "$TARGET" = "am3-s21" ]; then
    echo "Next (Wave 0c — S21 .135 dry-run):"
    echo "  dcent install 203.0.113.135 -f \"$OUTPUT_DIR/$TARBALL_NAME\" --artifact-dir <restore_verified_dir> --plan"
    echo ""
    echo "Then native NAND write is DESTRUCTIVE and operator-gated:"
    echo "  scripts/build_amlogic_native_install.sh --variant s21"
    echo "  flash_erase/nandwrite only after backup, readback, physical access, and reboot plan."
elif [ "$TARGET" = "am3-s21pro" ] || [ "$TARGET" = "am3-s21xp" ]; then
    echo "Experimental BM1370 artifact ready for $TARGET:"
    echo "  $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "No live write is authorized: exact EEPROM geometry, backup/readback,"
    echo "physical recovery, and an operator-approved bench plan remain required."
elif [ "$TARGET" = "am3-s19kpro" ]; then
    echo "Next (Phase K — S19k Pro .78 dry-run):"
    echo "  dcent install 203.0.113.78 -f \"$OUTPUT_DIR/$TARBALL_NAME\" --artifact-dir <restore_verified_dir> --plan"
    echo ""
    echo "Then Phase L (live install, DESTRUCTIVE — operator-gated):"
    echo "  dcent install 203.0.113.78 -f \"$OUTPUT_DIR/$TARBALL_NAME\" --artifact-dir <restore_verified_dir>"
    echo "  Add --accept-vnish-aml-rootfs-window only when the detected source is VNish"
    echo "  and the operator has separately acknowledged that source-specific route."
    echo ""
    echo "Preflight gate enforces: (a) BHB56902 0x05 0x11 EEPROM preamble,"
    echo "                          (b) APW121215f PSU fw=0x76,"
    echo "                          (c) Amlogic am3-aml NoPic platform identity."
# Added by Phase 4B (2026-05-15): am3-s19jpro-aml + am3-t21 are scaffold-only
# variants; no install route is registered yet and there is no live unit on
# the fleet. The tarball exists for build-pipeline / package-validator
# regression coverage until a bench unit is acquired and Phase 4C ships the
# matching revert-to-stock script.
elif [ "$TARGET" = "am3-s19jpro-aml" ]; then
    echo "Phase 4B scaffold target (am3-s19jpro-aml — no live unit yet):"
    echo "  Sysupgrade tarball: $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "No toolbox install route advertises this board target yet."
    echo "Pending: Phase 4C revert-to-stock + bench unit acquisition."
elif [ "$TARGET" = "am3-t21" ]; then
    echo "Phase 4B scaffold target (am3-t21 — no live unit yet):"
    echo "  Sysupgrade tarball: $OUTPUT_DIR/$TARBALL_NAME"
    echo ""
    echo "No toolbox install route advertises this board target yet."
    echo "Pending: Phase 4C revert-to-stock + bench unit acquisition."
# End Phase 4B
elif [ "$TARGET" = "am3-bb" ] || [ "$TARGET" = "am3-bb-s19jpro" ] || [ "$TARGET" = "am3-bb-s19jpro-payload" ]; then
    echo "Next (AM3 BB .79 SD-card first boot):"
    echo "  Inspect \"$OUTPUT_DIR/$TARBALL_NAME\""
    if [ -f "$OUTPUT_DIR/${TARBALL_NAME}.sig" ]; then
        echo "  Signature:    $OUTPUT_DIR/${TARBALL_NAME}.sig (ed25519)"
        echo "  Verify with:  openssl pkeyutl -verify -rawin -pubin \\"
        echo "                  -inkey release_ed25519.pub \\"
        echo "                  -sigfile \"$OUTPUT_DIR/${TARBALL_NAME}.sig\" \\"
        echo "                  -in \"$OUTPUT_DIR/$TARBALL_NAME\""
    fi
    echo "  Add verified AM335x boot artifacts (MLO, u-boot.img, uImage, DTB)."
    echo "  Image SD media manually with physical recovery available."
    echo ""
    echo "This tarball is NOT a NAND/sysupgrade package and contains no stock uart_trans.ko."
    if [ "$TARGET" = "am3-bb-s19jpro" ]; then
        echo "It should boot dcentrald with --am3-bb-mining plus rescue SSH and localhost MCP."
    fi
    echo "JTAG + serial recovery: see br2_external_dcentos/board/beaglebone/am3-bb/README.md"
elif [ "$TARGET" = "am3-bb-s19jpro-vnish" ]; then
    echo "Next (AM3 BB .79 VNish boot.bin SD prototype — Phase 1B):"
    echo "  Image:    $OUTPUT_DIR/$TARBALL_NAME"
    echo "  Manifest: $OUTPUT_DIR/dcentos-am3-bb-s19jpro-vnish-bootbin.manifest.json"
    echo ""
    echo "This is a Phase 1B prototype (Preparedness Sweep 2026-05-15). The .img"
    echo "embeds the captured VNish v1.2.6 boot.bin SD-stage U-Boot at sector 1"
    echo "of a FAT16 partition (label DCENTOS by default; pass --label ANTHILLOS"
    echo "to mirror VNish exactly)."
    echo ""
    echo "Boot flow at runtime: AM335x BootROM -> NAND U-Boot SPL -> SD fatload"
    echo "boot.bin @ 0x88000000 -> uImage @ 0x80200000 -> DTB @ 0x80f80000 ->"
    echo "uramdisk.image.gz @ 0x81000000 -> go 0x88000000."
    echo ""
    echo "Flash:  dd if=\"$OUTPUT_DIR/$TARBALL_NAME\" of=/dev/sdX bs=4M status=progress"
    echo "        (or DCENT_OS_Antminer/scripts/write_am3_bb_sd_physical_windows.ps1 as Administrator)"
    echo ""
    echo "DO NOT call this image cold-boot-proven until .79 boots it, exposes"
    echo "SSH/MCP/dashboard, and submits accepted shares from S82dcentrald."
else
    echo "Next (from runbook $PROJECT_DIR/docs/reviews/2026-04-16_flash_runbook_203.0.113.118.md):"
    echo "  scp -O \"$OUTPUT_DIR/$TARBALL_NAME\" root@203.0.113.118:/data/"
    echo "  ssh root@203.0.113.118 'sysupgrade --test /data/$TARBALL_NAME'"
fi
echo "==================================================================="
