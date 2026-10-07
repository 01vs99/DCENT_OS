#!/bin/sh
# Mount-free adversarial tests for stable sysupgrade package-input admission.
# Literal shell source needles below intentionally must not expand.
# shellcheck disable=SC2016

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-package-input.sh
WORK_ROOT=${TMPDIR:-/tmp}/dcent-sysupgrade-package-input-test.$$
SAFE_PARENT=$WORK_ROOT/stage
PACKAGE=$SAFE_PARENT/dcentos-sysupgrade.tar
failures=0
tests=0

cleanup()
{
    dcent_sysupgrade_input_close >/dev/null 2>&1 || true
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

# shellcheck source=/dev/null
. "$HELPER"

pass() { tests=$((tests + 1)); printf 'PASS: %s\n' "$1"; }
fail() { tests=$((tests + 1)); failures=$((failures + 1)); printf 'FAIL: %s\n' "$1" >&2; }
expect_success()
{
    _label=$1
    shift
    if "$@"; then pass "$_label"; else fail "$_label"; fi
}
expect_failure()
{
    _label=$1
    shift
    if "$@" >/dev/null 2>&1; then fail "$_label (unexpected success)"; else pass "$_label"; fi
}
reset_input()
{
    dcent_sysupgrade_input_close >/dev/null 2>&1 || true
}
make_package()
{
    _payload=$1
    rm -rf "$WORK_ROOT/build"
    mkdir -p "$WORK_ROOT/build/sysupgrade-am2-s19j"
    printf '%s\n' "$_payload" >"$WORK_ROOT/build/sysupgrade-am2-s19j/root"
    printf '%s\n' kernel >"$WORK_ROOT/build/sysupgrade-am2-s19j/kernel"
    tar cf "$PACKAGE" -C "$WORK_ROOT/build" sysupgrade-am2-s19j
    chmod 600 "$PACKAGE"
}

mkdir -p "$SAFE_PARENT"
chmod 700 "$SAFE_PARENT"

expect_success "path metadata inspection forces the C locale" \
    grep -Fq 'LC_ALL=C stat -c "$1" -- "$2"' "$HELPER"
expect_success "descriptor metadata inspection forces the C locale" \
    grep -Fq 'LC_ALL=C stat -Lc "$1" -- "$2"' "$HELPER"

TEST_UID=$(id -u)
TEST_GID=$(id -g)
expect_success "deployed input policy admits only uid 0" \
    test "$(dcent_sysupgrade_input_expected_uid)" = 0
expect_success "deployed input policy admits only gid 0" \
    test "$(dcent_sysupgrade_input_expected_gid)" = 0

# Test-local overrides exercise the complete lifecycle for root and non-root
# CI users.  They do not alter the sourced production helper.
dcent_sysupgrade_input_expected_uid() { printf '%s\n' "$TEST_UID"; }
dcent_sysupgrade_input_expected_gid() { printf '%s\n' "$TEST_GID"; }

make_package original
ORIGINAL_SHA=$(sha256sum "$PACKAGE" | awk '{print $1}')
ORIGINAL_SIZE=$(wc -c <"$PACKAGE" | tr -d '[:space:]')

expect_failure "relative package path is refused" \
    dcent_sysupgrade_input_open relative.tar
expect_failure "filesystem root is refused" \
    dcent_sysupgrade_input_open /

ln -s "$PACKAGE" "$SAFE_PARENT/package-link.tar"
expect_failure "symlink package is refused" \
    dcent_sysupgrade_input_open "$SAFE_PARENT/package-link.tar"

mkdir "$WORK_ROOT/real-parent"
cp "$PACKAGE" "$WORK_ROOT/real-parent/package.tar"
chmod 600 "$WORK_ROOT/real-parent/package.tar"
ln -s "$WORK_ROOT/real-parent" "$WORK_ROOT/linked-parent"
expect_failure "symlinked ancestor is refused" \
    dcent_sysupgrade_input_open "$WORK_ROOT/linked-parent/package.tar"

mkdir "$WORK_ROOT/writable-parent"
chmod 777 "$WORK_ROOT/writable-parent"
cp "$PACKAGE" "$WORK_ROOT/writable-parent/package.tar"
chmod 600 "$WORK_ROOT/writable-parent/package.tar"
expect_failure "non-sticky group/other-writable parent is refused" \
    dcent_sysupgrade_input_open "$WORK_ROOT/writable-parent/package.tar"

cp "$PACKAGE" "$SAFE_PARENT/writable.tar"
chmod 666 "$SAFE_PARENT/writable.tar"
expect_failure "group/other-writable package is refused" \
    dcent_sysupgrade_input_open "$SAFE_PARENT/writable.tar"

cp "$PACKAGE" "$SAFE_PARENT/executable.tar"
chmod 700 "$SAFE_PARENT/executable.tar"
expect_failure "executable package is refused" \
    dcent_sysupgrade_input_open "$SAFE_PARENT/executable.tar"

ln "$PACKAGE" "$SAFE_PARENT/hardlink.tar"
expect_failure "multiply-linked package is refused" \
    dcent_sysupgrade_input_open "$PACKAGE"
rm "$SAFE_PARENT/hardlink.tar"

expect_failure "wrong owner is refused by the metadata predicate" \
    _dcent_sysupgrade_input_validate_metadata "$((TEST_UID + 1))" "$TEST_GID" 600 1 "$ORIGINAL_SIZE" 'regular file'
expect_failure "wrong group is refused by the metadata predicate" \
    _dcent_sysupgrade_input_validate_metadata "$TEST_UID" "$((TEST_GID + 1))" 600 1 "$ORIGINAL_SIZE" 'regular file'
expect_failure "zero-byte input is refused by the metadata predicate" \
    _dcent_sysupgrade_input_validate_metadata "$TEST_UID" "$TEST_GID" 600 1 0 'regular file'
expect_failure "non-sticky writable ancestor mode is refused by the pure predicate" \
    _dcent_sysupgrade_input_validate_directory_metadata "$TEST_UID" "$TEST_GID" 777 directory
expect_success "root-owned sticky scratch ancestor is admitted by the pure predicate" \
    _dcent_sysupgrade_input_validate_directory_metadata 0 0 1777 directory

expect_success "root-owned-policy test package opens once on descriptor 9" \
    dcent_sysupgrade_input_open "$PACKAGE"
expect_success "published consumer path is the reserved proc descriptor" \
    test "$DCENT_SYSUPGRADE_INPUT_FD_PATH" = /proc/self/fd/9
expect_success "captured package size is exact" \
    test "$DCENT_SYSUPGRADE_INPUT_SIZE" = "$ORIGINAL_SIZE"
expect_success "captured package SHA-256 is exact" \
    test "$DCENT_SYSUPGRADE_INPUT_SHA256" = "$ORIGINAL_SHA"
expect_failure "a second open is refused while the descriptor is owned" \
    dcent_sysupgrade_input_open "$PACKAGE"
expect_success "immediate stability checkpoint succeeds" \
    dcent_sysupgrade_input_verify_unchanged

FD_SHA=$(sha256sum "$DCENT_SYSUPGRADE_INPUT_FD_PATH" | awk '{print $1}')
expect_success "BusyBox/GNU sha256sum reads the inherited descriptor path" \
    test "$FD_SHA" = "$ORIGINAL_SHA"
FD_SIZE=$(wc -c <"$DCENT_SYSUPGRADE_INPUT_FD_PATH" | tr -d '[:space:]')
expect_success "descriptor-backed wc starts at byte zero after sha256sum" \
    test "$FD_SIZE" = "$ORIGINAL_SIZE"
# The single quotes intentionally defer the descriptor read to the child.
# shellcheck disable=SC2016
expect_success "child POSIX shell inherits descriptor 9" \
    sh -c 'test -r /proc/self/fd/9 && test "$(wc -c </proc/self/fd/9)" -gt 0'
expect_success "tar lists through the inherited descriptor" \
    tar tf "$DCENT_SYSUPGRADE_INPUT_FD_PATH"
mkdir "$WORK_ROOT/extracted"
expect_success "tar extracts through the inherited descriptor" \
    tar xf "$DCENT_SYSUPGRADE_INPUT_FD_PATH" -C "$WORK_ROOT/extracted"
expect_success "descriptor-backed extraction produced the original payload" \
    grep -q '^original$' "$WORK_ROOT/extracted/sysupgrade-am2-s19j/root"
expect_success "tar/hash/extract reads leave the checkpoint stable" \
    dcent_sysupgrade_input_verify_unchanged

# Atomic pathname replacement cannot redirect the already-open descriptor.
mv "$PACKAGE" "$SAFE_PARENT/original.saved"
make_package replacement
PINNED_ROOT=$(tar xOf "$DCENT_SYSUPGRADE_INPUT_FD_PATH" sysupgrade-am2-s19j/root |
    tr -d '\r\n')
PATH_ROOT=$(tar xOf "$PACKAGE" sysupgrade-am2-s19j/root | tr -d '\r\n')
expect_success "descriptor remains on the original inode after path replacement" \
    test "$PINNED_ROOT" = original
expect_success "replacement pathname resolves to different bytes" \
    test "$PATH_ROOT" = replacement
expect_failure "stability checkpoint refuses pathname replacement" \
    dcent_sysupgrade_input_verify_unchanged
reset_input

# Truncating the same inode changes the pinned descriptor too.  This proves
# the documented Linux limit and the fail-closed checkpoint behavior.
mv "$SAFE_PARENT/original.saved" "$PACKAGE"
chmod 600 "$PACKAGE"
expect_success "original package reopens after replacement test" \
    dcent_sysupgrade_input_open "$PACKAGE"
: >"$PACKAGE"
expect_success "pinned descriptor observes same-inode truncation" \
    test "$(wc -c <"$DCENT_SYSUPGRADE_INPUT_FD_PATH")" = 0
expect_failure "stability checkpoint detects same-inode truncation" \
    dcent_sysupgrade_input_verify_unchanged
reset_input

printf '%s' content-before >"$PACKAGE"
chmod 600 "$PACKAGE"
expect_success "same-size mutation fixture opens" \
    dcent_sysupgrade_input_open "$PACKAGE"
# Both strings have equal length, so metadata size stays constant and only the
# content digest can detect the mutation.
printf '%s' 'content-after!' | dd of="$PACKAGE" bs=1 conv=notrunc 2>/dev/null
expect_success "same-size mutation keeps descriptor metadata size" \
    test "$(stat -Lc %s "$DCENT_SYSUPGRADE_INPUT_FD_PATH")" = "$DCENT_SYSUPGRADE_INPUT_SIZE"
expect_failure "SHA-256 checkpoint detects same-size content mutation" \
    dcent_sysupgrade_input_verify_unchanged
reset_input

make_package unlink-test
expect_success "unlink fixture opens" dcent_sysupgrade_input_open "$PACKAGE"
rm "$PACKAGE"
expect_success "open descriptor remains readable after unlink" \
    tar tf "$DCENT_SYSUPGRADE_INPUT_FD_PATH"
expect_failure "stability checkpoint refuses an unlinked source path" \
    dcent_sysupgrade_input_verify_unchanged
reset_input

make_package close-test
expect_success "close fixture opens" dcent_sysupgrade_input_open "$PACKAGE"
expect_success "close is idempotent" dcent_sysupgrade_input_close
expect_success "close clears public ownership state" \
    test "$DCENT_SYSUPGRADE_INPUT_OPEN" = 0
expect_failure "descriptor is not inherited after close" \
    sh -c 'test -e /proc/self/fd/9 || test -L /proc/self/fd/9'
expect_success "second close remains harmless" dcent_sysupgrade_input_close

caller_line()
{
    _dcent_input_caller=$1
    _dcent_input_needle=$2
    grep -nF "$_dcent_input_needle" "$_dcent_input_caller" |
        sed -n '1s/:.*//p'
}

caller_has_canonical_attach_wrapper()
{
    _dcent_input_caller=$1
    awk '
        /^dcent_ubi_attach_mtd\(\) \{/ {
            in_wrapper = 1
            definitions++
            next
        }
        in_wrapper && /^}/ {
            in_wrapper = 0
            next
        }
        in_wrapper && /^[[:space:]]*dcent_ubi_node_admit \/sys\/class\/misc\/ubi_ctrl\/dev \/dev ubi_ctrl \|\| return 1$/ {
            admissions++
            admission_line = NR
        }
        /^[[:space:]]*ubiattach -m / {
            raw_attaches++
            if (!in_wrapper) raw_attach_outside_wrapper++
            if (in_wrapper) attach_line = NR
        }
        END {
            exit !(definitions == 1 && admissions == 1 && raw_attaches == 1 &&
                   raw_attach_outside_wrapper == 0 && admission_line < attach_line)
        }
    ' "$_dcent_input_caller"
}

caller_input_order_is_safe()
{
    _dcent_input_caller=$1
    _dcent_input_parse=$(caller_line "$_dcent_input_caller" 'ROOTFS_ORIGINAL=$ROOTFS')
    _dcent_input_open=$(caller_line "$_dcent_input_caller" 'if ! dcent_sysupgrade_input_open "$ROOTFS_ORIGINAL"; then')
    _dcent_input_tar=$(caller_line "$_dcent_input_caller" 'if tar tf "$ROOTFS" >/dev/null 2>&1; then')
    case "$_dcent_input_parse:$_dcent_input_open:$_dcent_input_tar" in
        *[!0-9:]*|*:*:*:*|::*|*::) return 1 ;;
    esac
    [ "$_dcent_input_parse" -lt "$_dcent_input_open" ] &&
        [ "$_dcent_input_open" -lt "$_dcent_input_tar" ]
}

caller_cleanup_closes_before_workspace()
{
    _dcent_input_caller=$1
    _dcent_input_close=$(caller_line "$_dcent_input_caller" 'if ! dcent_sysupgrade_input_close; then')
    _dcent_input_workspace=$(caller_line "$_dcent_input_caller" 'if ! dcent_sysupgrade_workspace_cleanup "$PROC_MOUNTS_PATH"; then')
    case "$_dcent_input_close:$_dcent_input_workspace" in
        *[!0-9:]*|:|*:|*:*:*) return 1 ;;
    esac
    [ "$_dcent_input_close" -lt "$_dcent_input_workspace" ]
}

caller_packaged_close_precedes_ubi()
{
    _dcent_input_caller=$1
    _dcent_input_payload_hash=$(caller_line "$_dcent_input_caller" 'if ! verify_sha256 "$PACKAGE_KERNEL"')
    _dcent_input_package_close=$(grep -n '^    verify_and_close_sysupgrade_input || exit 1$' \
        "$_dcent_input_caller" | sed -n '1s/:.*//p')
    _dcent_input_first_ubi=$(caller_line "$_dcent_input_caller" 'if ! dcent_ubi_attach_mtd "$INACTIVE_MTD" 1')
    case "$_dcent_input_payload_hash" in ''|*[!0-9]*) return 1 ;; esac
    case "$_dcent_input_package_close" in ''|*[!0-9]*) return 1 ;; esac
    case "$_dcent_input_first_ubi" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_dcent_input_payload_hash" -lt "$_dcent_input_package_close" ] &&
        [ "$_dcent_input_package_close" -lt "$_dcent_input_first_ubi" ]
}

caller_raw_close_follows_readback()
{
    _dcent_input_caller=$1
    _dcent_input_readback=$(caller_line "$_dcent_input_caller" 'preflip_verify_volume rootfs /dev/ubi1_1 "$ROOTFS"')
    _dcent_input_checkpoint=$(caller_line "$_dcent_input_caller" 'verify_and_close_sysupgrade_input || preflip_fail "sysupgrade input stability checkpoint failed after inactive-slot readback."')
    case "$_dcent_input_readback:$_dcent_input_checkpoint" in
        *[!0-9:]*|:|*:|*:*:*) return 1 ;;
    esac
    [ "$_dcent_input_checkpoint" -eq $((_dcent_input_readback + 1)) ]
}

caller_raw_checkpoint_precedes_ubi()
{
    _dcent_input_caller=$1
    _dcent_input_guard=$(caller_line "$_dcent_input_caller" 'if [ "$PACKAGE_INPUT_IS_TAR" -eq 0 ]; then')
    _dcent_input_checkpoint=$(caller_line "$_dcent_input_caller" 'verify_sysupgrade_input_unchanged || exit 1')
    _dcent_input_absence=$(caller_line "$_dcent_input_caller" 'if ! dcent_ubi_attachment_require_absent /sys/class/ubi 1 "$INACTIVE_MTD"; then')
    _dcent_input_first_ubi=$(caller_line "$_dcent_input_caller" 'if ! dcent_ubi_attach_mtd "$INACTIVE_MTD" 1')
    case "$_dcent_input_guard" in ''|*[!0-9]*) return 1 ;; esac
    case "$_dcent_input_checkpoint" in ''|*[!0-9]*) return 1 ;; esac
    case "$_dcent_input_absence" in ''|*[!0-9]*) return 1 ;; esac
    case "$_dcent_input_first_ubi" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_dcent_input_guard" -eq $((_dcent_input_checkpoint - 1)) ] &&
        [ "$_dcent_input_checkpoint" -lt "$_dcent_input_absence" ] &&
        [ "$_dcent_input_absence" -lt "$_dcent_input_first_ubi" ]
}

for _caller_spec in \
    "am1-s9:$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s17pro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s19jpro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade" \
    "am2-s19pro:$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade"
do
    _caller_label=${_caller_spec%%:*}
    _caller_path=${_caller_spec#*:}
    expect_success "$_caller_label pins the canonical package-input helper" \
        grep -Fq 'PACKAGE_INPUT_HELPER="/usr/libexec/dcentos/sysupgrade-package-input.sh"' "$_caller_path"
    expect_success "$_caller_label permits helper override only through the marker-guarded harness block" \
        grep -Fq 'PACKAGE_INPUT_HELPER="${DCENT_SYSUPGRADE_PACKAGE_INPUT_HELPER:-$PACKAGE_INPUT_HELPER}"' "$_caller_path"
    expect_success "$_caller_label preserves the operator-supplied path for diagnostics" \
        grep -Fq 'ROOTFS_ORIGINAL=$ROOTFS' "$_caller_path"
    expect_success "$_caller_label explicitly refuses relative input paths" \
        grep -Fq 'sysupgrade input must be an absolute path' "$_caller_path"
    expect_success "$_caller_label opens input after parsing and before its first tar read" \
        caller_input_order_is_safe "$_caller_path"
    expect_failure "$_caller_label never command-substitutes descriptor admission" \
        grep -F '=$(dcent_sysupgrade_input_open' "$_caller_path"
    expect_success "$_caller_label cleanup closes input before workspace removal" \
        caller_cleanup_closes_before_workspace "$_caller_path"
    expect_success "$_caller_label routes the first UBI mutation through the admitted control-node wrapper" \
        caller_has_canonical_attach_wrapper "$_caller_path"
    expect_success "$_caller_label closes a packaged tar after payload hashes and before UBI mutation" \
        caller_packaged_close_precedes_ubi "$_caller_path"
    expect_success "$_caller_label rechecks raw input immediately before first UBI mutation" \
        caller_raw_checkpoint_precedes_ubi "$_caller_path"
    expect_success "$_caller_label keeps raw input pinned through rootfs readback" \
        caller_raw_close_follows_readback "$_caller_path"
done

NANDSIM_HARNESS=$PROJECT_ROOT/scripts/sysupgrade_offline_nandsim_harness.sh
expect_success "nandsim harness passes the package-input helper through the guarded override" \
    grep -Fq 'DCENT_SYSUPGRADE_PACKAGE_INPUT_HELPER=$PACKAGE_INPUT_HELPER' "$NANDSIM_HARNESS"
expect_success "nandsim harness copies host/9p input into its trusted workspace" \
    grep -Fq 'cp -- "$PACKAGE_SOURCE" "$TRUSTED_PACKAGE"' "$NANDSIM_HARNESS"
expect_success "nandsim trusted package is normalized to root ownership" \
    grep -Fq 'chown 0:0 "$TRUSTED_PACKAGE"' "$NANDSIM_HARNESS"
expect_success "nandsim trusted package is normalized to mode 0600" \
    grep -Fq 'chmod 0600 "$TRUSTED_PACKAGE"' "$NANDSIM_HARNESS"
expect_success "nandsim verifies staging-copy byte equality" \
    grep -Fq 'cmp -s "$PACKAGE_SOURCE" "$TRUSTED_PACKAGE"' "$NANDSIM_HARNESS"

if [ "$failures" -ne 0 ]; then
    printf '\nsysupgrade package-input tests failed: %s/%s failed\n' \
        "$failures" "$tests" >&2
    exit 1
fi
printf '\nsysupgrade package-input tests passed: %s assertions\n' "$tests"
