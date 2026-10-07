#!/bin/sh
#
# revert_to_stock_am3_aml_s19k.sh — legacy evidence-only classifier for a
# hypothetical S19k Pro Amlogic ARM64 uImage window payload. It does not
# establish stock payload identity and cannot return a unit to stock.
#
#  W12-B sibling of revert_to_stock_am3_aml_s21.sh. Same
# Amlogic uImage flash mechanism as S21, using scripts/lib/am3_geometry.sh. The
# difference (BM1366 + BHB56902 + APW121215f fw=0x76) is hashboard-side
# and doesn't change the flash primitives. Per
# s19k pro live probe 78 2026 04 29 rule.
#
# The exact held evidence-bound stock route is the encrypted three-member
# AML factory-SD package admitted by s19k_aml_stock_recovery_plan.py. This
# legacy classifier cannot validate uImage CRC or vendor identity. Target
# mutation is intentionally unreachable (`CLEAR_FOR_FLASH=false`); this is not a code-complete revert.
#
# Usage:
#   ./revert_to_stock_am3_aml_s19k.sh [--dry-run] <firmware_image.tar.gz> <sha256>

set -eu
# POSIX-sh (BusyBox ash) compatible.

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ ! -r "$SCRIPT_DIR/lib/am3_geometry.sh" ]; then
    echo "ERROR: missing shared AM3 geometry file: $SCRIPT_DIR/lib/am3_geometry.sh" >&2
    echo "Copy scripts/lib/am3_geometry.sh beside this revert helper before using it." >&2
    exit 1
fi
. "$SCRIPT_DIR/lib/am3_geometry.sh"

ROOTFS_MTD="$DCENT_AM3_ROOTFS_MTD"
ROOTFS_OFFSET="$DCENT_AM3_ROOTFS_OFFSET_HEX"
UIMAGE_MAGIC_HEX="27051956"
MAX_ARCHIVE_BYTES=67108864
MAX_UIMAGE_BYTES=41943040
PLATFORM_FILE=${DCENTOS_PLATFORM_FILE:-/etc/dcentos-platform}
BOARD_TARGET_FILE=${DCENTOS_BOARD_TARGET_FILE:-/etc/dcentos/board_target}
DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

command -v mktemp >/dev/null 2>&1 || {
    echo "ERROR: mktemp missing; refusing non-private stock-revert classification" >&2
    exit 1
}
umask 077
REVERT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/dcent-s19k-stock-revert.XXXXXX") || {
    echo "ERROR: could not create private stock-revert transaction directory" >&2
    exit 1
}
EXTRACT_DIR="$REVERT_TMP/extracted"
REVERT_PLAN="$REVERT_TMP/REVERT_COMMIT_PLAN.txt"
cleanup_revert_tmp() {
    rm -rf "$REVERT_TMP" 2>/dev/null || true
}
trap cleanup_revert_tmp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# /242: firstboot-only is refused. Plan names recover_env.
# dry_run writes and prints the plan from a private transaction directory
# before GPIO/nandwrite and exits 0. No fixed /tmp path is removed or replaced.
write_revert_commit_plan() {
    _dry=$1
    _nand=$2
    {
        echo "schema=dcentos.amlogic-stock-image-revert/v1"
        echo "nandwrite_target=root"
        echo "rootfs_local=0x05100000"
        echo "rootfs_window=0x02800000"
        echo "commit=refused_firstboot_only"
        echo "bootcmd_reads_firstboot=false"
        echo "bootm_mtd2=false"
        echo "mix_flag_02=false"
        echo "uimage_write_is_not_recover_to_stock=true"
        echo "legacy_uimage_classifier_only=true"
        echo "uimage_crc_verified=false"
        echo "stock_payload_identity_verified=false"
        echo "vendor_factory_sd_is_only_evidence_bound_stock_route=true"
        echo "stock_return=recover_env_nandrecovery"
        echo "recover_env_source=nandrecovery_env.bin"
        echo "recover_env_ram=0x01060000"
        echo "nandrecovery_env_offset=0x0B000000"
        echo "env_size=0x10000"
        echo "uboot_recover_to_stock=run recover_env; nand erase.part nvdata; reset"
        echo "flag_02_helper=s19k_write_recovery_flag.sh"
        echo "does_not_arm_flag_02=true"
        echo "dry_run=$_dry"
        echo "nandwrite=$_nand"
        echo "gpio_write=$_nand"
        echo "execute=CLEAR_FOR_FLASH"
        echo "clear_for_flash=false"
    } > "$REVERT_PLAN"
    echo "  private_plan=$REVERT_PLAN dry_run=$_dry nandwrite=$_nand"
    cat "$REVERT_PLAN"
}

echo "==============================================================="
echo "  REFUSED legacy ARM64 uImage classifier (S19k Pro / am3-aml)"
echo "==============================================================="
echo ""

CURRENT_SLOT=$(fw_printenv -n dcent_boot_slot 2>/dev/null || echo "1")
echo "Current dcent_boot_slot: $CURRENT_SLOT"
echo ""

FW_IMAGE="${1:-}"
EXPECTED_SHA256=$(printf '%s' "${2:-}" | tr 'A-F' 'a-f')
if [ -z "$FW_IMAGE" ]; then
    echo "ERROR: No firmware image specified."
    echo "Usage: $0 [--dry-run] /path/to/Antminer-S19k-Pro-merge-release-XXXXX.tar.gz <sha256>"
    exit 1
fi
if [ ${#EXPECTED_SHA256} -ne 64 ]; then
    echo "ERROR: stock revert requires expected SHA-256 (64 hex chars) as argv2" >&2
    exit 1
fi
case "$EXPECTED_SHA256" in
    *[!0-9a-f]*) echo "ERROR: expected SHA-256 is not hex" >&2; exit 1 ;;
esac

if [ ! -f "$FW_IMAGE" ] || [ -L "$FW_IMAGE" ]; then
    echo "ERROR: firmware image must be a real regular file, not a symlink: $FW_IMAGE"
    exit 1
fi

echo "Untrusted candidate archive: $FW_IMAGE"
echo "Image size: $(ls -lh "$FW_IMAGE" | awk '{print $5}')"
echo ""
FW_ARCHIVE_LEN=$(wc -c < "$FW_IMAGE" | tr -d ' \t\r\n')
case "$FW_ARCHIVE_LEN" in
    ''|*[!0-9]*)
        echo "ERROR: cannot determine candidate archive size" >&2
        exit 1
        ;;
esac
if [ "$FW_ARCHIVE_LEN" -gt "$MAX_ARCHIVE_BYTES" ]; then
    echo "ERROR: candidate archive is $FW_ARCHIVE_LEN bytes, above private-copy cap $MAX_ARCHIVE_BYTES" >&2
    exit 1
fi

echo "Step 0: identity / geometry preflight (before REVERT prompt)..."
if [ -r /etc/dcentos/tmp_deploy ]; then
    echo "ERROR: /etc/dcentos/tmp_deploy leftover — refuse stock revert after /tmp bench deploy" >&2
    exit 1
fi
if [ ! -r "$PLATFORM_FILE" ] || [ ! -r "$BOARD_TARGET_FILE" ]; then
    echo "ERROR: missing exact live platform:target identity; refuse stock revert" >&2
    exit 1
fi
LIVE_PLATFORM=$(tr -d ' \t\r\n' < "$PLATFORM_FILE")
BT=$(tr -d ' \t\r\n' < "$BOARD_TARGET_FILE")
if [ "$LIVE_PLATFORM:$BT" != "am3-aml-s19k:am3-s19k" ]; then
    echo "ERROR: live platform:target='$LIVE_PLATFORM:$BT' is not exact am3-aml-s19k:am3-s19k; refuse stock revert" >&2
    exit 1
fi
OFFSET_DEC=$((ROOTFS_OFFSET))
SIZE_SUM_WINDOW_DEC=$((0x05700000))
SIZE_SUM_FLAG_DEC=$((0x05300000))
SIZE_SUM_BASE_DEC=$((0x06100000))
ADMITTED_LOCAL_DEC=$((0x05100000))
if [ "$OFFSET_DEC" -eq "$SIZE_SUM_WINDOW_DEC" ] || [ "$OFFSET_DEC" -eq "$SIZE_SUM_FLAG_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is size-sum pairing 0x05700000/0x05300000; refuse as revert nandwrite base" >&2
    exit 1
fi
if [ "$OFFSET_DEC" -eq "$SIZE_SUM_BASE_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is size-sum 0x06100000 without the 6MiB hole; refuse as revert base" >&2
    exit 1
fi
if [ "$OFFSET_DEC" -ne "$ADMITTED_LOCAL_DEC" ]; then
    echo "ERROR: $ROOTFS_OFFSET is not admitted local 0x05100000 (nandrootfs − physical mtd5 0x06700000)" >&2
    exit 1
fi
echo "  identity=$LIVE_PLATFORM:$BT tmp_deploy=absent rootfs_offset=$ROOTFS_OFFSET"

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum missing; refusing expected-SHA stock revert." >&2
    exit 1
fi
PRIVATE_FW="$REVERT_TMP/stock-candidate.tar.gz"
cp "$FW_IMAGE" "$PRIVATE_FW" || {
    echo "ERROR: failed to snapshot firmware into the private transaction" >&2
    exit 1
}
chmod 0600 "$PRIVATE_FW" 2>/dev/null || true
ACTUAL_SHA256=$(sha256sum "$PRIVATE_FW" | awk '{print $1}' | tr 'A-F' 'a-f')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: private firmware snapshot SHA-256 does not match authority argv." >&2
    echo "  expected: $EXPECTED_SHA256" >&2
    echo "  actual:   $ACTUAL_SHA256" >&2
    exit 1
fi
echo "Firmware SHA-256 verified on private immutable-for-this-process snapshot."

echo "Step 1: Streaming the single named uImage candidate (classify before REVERT)..."
TOC="$REVERT_TMP/archive.toc"
TOC_VERBOSE="$REVERT_TMP/archive.verbose"
CANDIDATES="$REVERT_TMP/uimage.candidates"
(ulimit -f 2048 && tar -tzf "$PRIVATE_FW" > "$TOC") || {
    echo "ERROR: firmware archive TOC is unreadable" >&2
    exit 1
}
(ulimit -f 4096 && tar -tvzf "$PRIVATE_FW" > "$TOC_VERBOSE") || {
    echo "ERROR: firmware archive typed TOC is unreadable" >&2
    exit 1
}
if [ ! -s "$TOC" ]; then
    echo "ERROR: firmware archive TOC is empty" >&2
    exit 1
fi
if LC_ALL=C grep -Eq '^h' "$TOC_VERBOSE"; then
    echo "ERROR: firmware archive contains hard-linked files; refusing streamed classification" >&2
    exit 1
fi
if LC_ALL=C grep -Eq '^[lbcps]' "$TOC_VERBOSE"; then
    echo "ERROR: firmware archive contains link or device members; refusing streamed classification" >&2
    exit 1
fi
if LC_ALL=C grep -nEv '^[A-Za-z0-9._/+@=-]+/?$' "$TOC" >/dev/null 2>&1; then
    echo "ERROR: archive contains a non-canonical member name; refuse extraction" >&2
    exit 1
fi
while IFS= read -r MEMBER; do
    case "$MEMBER" in
        /*|-*|*/-*|..|../*|*/..|*/../*)
            echo "ERROR: archive member escapes its root: $MEMBER" >&2
            exit 1
            ;;
    esac
done < "$TOC"
DUPLICATE_MEMBER=$(sort "$TOC" | uniq -d | head -n 1)
if [ -n "$DUPLICATE_MEMBER" ]; then
    echo "ERROR: archive repeats member name: $DUPLICATE_MEMBER" >&2
    exit 1
fi
grep -E '(^|/)(rootfs_uImage[^/]*|[^/]*uImage[^/]*|rootfs[^/]*\.bin)$' "$TOC" > "$CANDIDATES" || true
CANDIDATE_COUNT=$(wc -l < "$CANDIDATES" | tr -d ' \t\r\n')
if [ "$CANDIDATE_COUNT" != 1 ]; then
    echo "ERROR: firmware archive must contain exactly one uImage-like candidate (got $CANDIDATE_COUNT)" >&2
    exit 1
fi
UIMAGE_MEMBER=$(sed -n '1p' "$CANDIDATES")
UIMAGE_REAL="$REVERT_TMP/uimage.candidate"
# BusyBox 1.37 tar `-O` streams the named member to stdout. It avoids materializing
# archive paths, links, devices, or sibling files even in this refused classifier.
# RLIMIT_FSIZE caps the private output before a compressed payload can fill /tmp.
(ulimit -f 81920 && tar -xOzf "$PRIVATE_FW" -- "$UIMAGE_MEMBER" > "$UIMAGE_REAL") || {
    echo "ERROR: could not stream the exact uImage candidate from the private archive" >&2
    rm -f "$UIMAGE_REAL"
    exit 1
}
[ -f "$UIMAGE_REAL" ] && [ ! -L "$UIMAGE_REAL" ] || {
    echo "ERROR: private uImage candidate is not a regular file" >&2
    exit 1
}
POST_EXTRACT_SHA256=$(sha256sum "$PRIVATE_FW" | awk '{print $1}' | tr 'A-F' 'a-f')
[ "$POST_EXTRACT_SHA256" = "$ACTUAL_SHA256" ] || {
    echo "ERROR: private firmware snapshot changed during classification" >&2
    exit 1
}

HEAD8=$(head -c 8 "$UIMAGE_REAL" | od -An -tx1 | tr -d ' \n')
case "$HEAD8" in
    414e44524f494421*)
        echo "ERROR: ANDROID! boot.img is not an mtd5 uImage; refuse nandwrite" >&2
        rm -rf "$EXTRACT_DIR"
        exit 1
        ;;
esac
HEAD_HEX=$(printf '%s' "$HEAD8" | cut -c1-8)
if [ "$HEAD_HEX" != "$UIMAGE_MAGIC_HEX" ]; then
    echo "ERROR: rootfs payload lacks uImage magic 27051956 (got: $HEAD_HEX)"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
ARCH_HEX=$(dd if="$UIMAGE_REAL" bs=1 skip=29 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$ARCH_HEX" != "16" ]; then
    echo "ERROR: uImage IH_ARCH=$ARCH_HEX is not ARM64 (16); refuse nandwrite" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
UIMAGE_LEN=$(wc -c < "$UIMAGE_REAL" | tr -d ' \t\r\n')
if [ "$UIMAGE_LEN" -gt "$MAX_UIMAGE_BYTES" ]; then
    echo "ERROR: uImage ${UIMAGE_LEN} B exceeds 0x02800000 window; refuse nandwrite" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
IH_SIZE=$(dd if="$UIMAGE_REAL" bs=1 skip=12 count=4 2>/dev/null | \
    od -An -tu1 | awk '{ print ($1 * 16777216) + ($2 * 65536) + ($3 * 256) + $4 }')
case "$IH_SIZE" in
    ''|*[!0-9]*)
        echo "ERROR: uImage header does not contain a readable big-endian ih_size" >&2
        exit 1
        ;;
esac
EXPECTED_UIMAGE_LEN=$((IH_SIZE + 64))
if [ "$UIMAGE_LEN" -ne "$EXPECTED_UIMAGE_LEN" ]; then
    echo "ERROR: uImage length=$UIMAGE_LEN does not exactly equal 64+ih_size=$EXPECTED_UIMAGE_LEN" >&2
    exit 1
fi
echo "  payload uImage IH_ARCH=ARM64 exact_header_length=$UIMAGE_LEN classified"
echo "  classifier limits: CRC and stock payload identity are unverified; NAND mutation remains refused"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] writing REVERT_COMMIT_PLAN before GPIO/nandwrite..."
    echo "[DRY RUN] dry_run=true nandwrite=false gpio_write=false"
    write_revert_commit_plan true false
    echo "[DRY RUN] no GPIO write, no nandwrite; refusing firstboot-only"
    echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2."
    rm -rf "$EXTRACT_DIR"
    exit 0
fi

echo "WARNING: This would write an identity-unproven ARM64 uImage to $ROOTFS_MTD"
echo "         offset $ROOTFS_OFFSET (uImage rootfs). This nandwrite is"
echo "         NOT recover_to_stock / mtd2. firstboot-only commit is refused."
echo ""
printf "Type 'REVERT' to proceed: "
read CONFIRM
if [ "$CONFIRM" != "REVERT" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
# : firstboot-only is not a recover commit, and flag 0x02
# execute stays FLASH-gated. Do not GPIO/nandwrite then refuse.
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "ERROR: CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/nandwrite/fw_setenv."
    write_revert_commit_plan false false
    echo "ERROR: refusing firstboot-only revert commit; .78 bootcmd never reads firstboot" >&2
    echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2." >&2
    echo "Stock-return is recover_to_stock (recover_env + nand erase.part nvdata)." >&2
    echo "This script does NOT arm flag 0x02 and does NOT fw_setenv firstboot." >&2
    echo "Use s19k_write_recovery_flag.sh --value 0x02 after CRC-admitting nandrecovery_env.bin." >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

trap 'echo "INTERRUPTED -- forcing reboot via sysrq to recover into a clean boot state."; echo b > /proc/sysrq-trigger 2>/dev/null || reboot -f' INT TERM HUP

echo "Step 1c: NAND/env tool preflight (before any NAND write)..."
if ! command -v nandwrite >/dev/null 2>&1; then
    echo "ERROR: nandwrite missing; refuse NAND write" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
if ! command -v fw_setenv >/dev/null 2>&1; then
    echo "ERROR: fw_setenv missing (Braiins L3); refuse NAND write before env-flip is possible" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
if ! command -v nanddump >/dev/null 2>&1; then
    echo "ERROR: nanddump missing; refuse NAND write without readback" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 1b: GPIO437 SafeOff (am3-s19k-active-low, value=1) before NAND write..."
PWR_GPIO=437
SYS=/sys/class/gpio
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "$PWR_GPIO" > "$SYS/export" 2>/dev/null || true
fi
if [ ! -d "$SYS/gpio$PWR_GPIO" ]; then
    echo "ERROR: gpio437 missing after export — refusing stock revert NAND write" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
echo 0 > "$SYS/gpio$PWR_GPIO/active_low"
echo high > "$SYS/gpio$PWR_GPIO/direction"
echo 1 > "$SYS/gpio$PWR_GPIO/value"
VAL=$(cat "$SYS/gpio$PWR_GPIO/value")
if [ "$VAL" != "1" ]; then
    echo "ERROR: gpio437 value=$VAL after SafeOff (want 1 / DISABLE on am3-s19k)" >&2
    rm -rf "$EXTRACT_DIR"
    exit 1
fi
echo "  gpio437 SafeOff OK polarity=am3-s19k-active-low value=$VAL"

echo "Step 2: Writing uImage to $ROOTFS_MTD offset $ROOTFS_OFFSET..."
if ! nandwrite -p -s "$ROOTFS_OFFSET" "$ROOTFS_MTD" "$UIMAGE_REAL"; then
    echo "ERROR: nandwrite failed -- rootfs slot may be partially overwritten."
    echo "DO NOT POWER CYCLE -- dcent_boot_slot has NOT been flipped."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 3: Post-write uImage magic readback..."
WROTE_HEX=$(nanddump -s "$ROOTFS_OFFSET" -l 4 "$ROOTFS_MTD" 2>/dev/null | tail -c 4 | od -An -tx1 | tr -d ' \n')
if [ "$WROTE_HEX" != "$UIMAGE_MAGIC_HEX" ]; then
    echo "ERROR: post-write readback at $ROOTFS_OFFSET lacks uImage magic 27051956 (got: $WROTE_HEX)"
    echo "DO NOT POWER CYCLE -- dcent_boot_slot has NOT been flipped."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

echo "Step 4: Revert commit plan (refusing firstboot-only)..."
# : lab-unit bootcmd never reads firstboot. Corpus stock-return is
# recover_to_stock = recover_env (nandrecovery_env @ 0x0B000000 → RAM
# 0x01060000, env import 0x10000) + nand erase.part nvdata, armed by
# flag 0x02 via s19k_write_recovery_flag.sh. This uImage nandwrite is
# NOT recover_to_stock and does NOT boot mtd2. Mixing firstboot+0x02 is
# refused. Execute of flag 0x02 stays CLEAR_FOR_FLASH=false.
write_revert_commit_plan false true
echo "ERROR: refusing firstboot-only revert commit; .78 bootcmd never reads firstboot" >&2
echo "This nandwrite is NOT recover_to_stock and does NOT boot mtd2." >&2
echo "Stock-return is recover_to_stock (recover_env + nand erase.part nvdata)." >&2
echo "This script does NOT arm flag 0x02 and does NOT fw_setenv firstboot." >&2
echo "Use s19k_write_recovery_flag.sh --value 0x02 after CRC-admitting nandrecovery_env.bin." >&2
rm -rf "$EXTRACT_DIR"
exit 1
