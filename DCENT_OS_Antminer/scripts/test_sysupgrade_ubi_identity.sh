#!/bin/sh
# Mount-free tests for the Zynq inactive-slot UBI identity admission helper.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-ubi-identity.sh
WORK_ROOT=${TMPDIR:-/tmp}/dcent-sysupgrade-ubi-identity-test.$$
SYSFS_ROOT=$WORK_ROOT/sys/class/ubi
failures=0
tests=0

cleanup()
{
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

write_attr()
{
    printf '%s\n' "$2" >"$1"
}

make_fixture()
{
    rm -rf "$WORK_ROOT"
    mkdir -p "$SYSFS_ROOT/ubi1" \
        "$SYSFS_ROOT/ubi1_0" "$SYSFS_ROOT/ubi1_1" "$SYSFS_ROOT/ubi1_2"
    write_attr "$SYSFS_ROOT/ubi1/mtd_num" 8
    write_attr "$SYSFS_ROOT/ubi1/volumes_count" 3
    write_attr "$SYSFS_ROOT/ubi1_0/name" kernel
    write_attr "$SYSFS_ROOT/ubi1_0/type" dynamic
    write_attr "$SYSFS_ROOT/ubi1_1/name" rootfs
    write_attr "$SYSFS_ROOT/ubi1_1/type" dynamic
    write_attr "$SYSFS_ROOT/ubi1_2/name" rootfs_data
    write_attr "$SYSFS_ROOT/ubi1_2/type" dynamic
}

admit_fixture()
{
    dcent_ubi_identity_admit "$SYSFS_ROOT" 1 8 3 dynamic dynamic dynamic
}

make_absent_fixture()
{
    rm -rf "$WORK_ROOT"
    mkdir -p "$SYSFS_ROOT/ubi0"
    write_attr "$SYSFS_ROOT/ubi0/mtd_num" 7
}

admit_attachment_absence()
{
    dcent_ubi_attachment_require_absent "$SYSFS_ROOT" 1 8
}

caller_has_identity_gate()
{
    _caller=$1
    grep -Fq 'UBI_IDENTITY_HELPER="/usr/libexec/dcentos/sysupgrade-ubi-identity.sh"' \
        "$_caller" || return 1
    grep -Fq 'DCENT_SYSUPGRADE_UBI_IDENTITY_HELPER' "$_caller" || return 1
    # This is the literal caller source statement, not a local expansion.
    # shellcheck disable=SC2016
    grep -Fq '. "$UBI_IDENTITY_HELPER"' "$_caller" || return 1
    [ "$(grep -Fxc 'if ! dcent_ubi_attachment_require_absent /sys/class/ubi 1 "$INACTIVE_MTD"; then' "$_caller")" -eq 1 ] || return 1
    ! grep -Fq 'dcent_ubi_detach_mtd' "$_caller" || return 1
    awk '
        /^dcent_ubi_semantic_identity_admit\(\) \{/ {
            in_identity_wrapper = 1
            identity_wrapper_definitions++
            next
        }
        in_identity_wrapper && /^}/ {
            in_identity_wrapper = 0
            next
        }
        in_identity_wrapper && /^[[:space:]]*dcent_ubi_identity_admit \/sys\/class\/ubi "\$1" "\$2" 3/ {
            raw_identity_admissions++
        }
        /^dcent_ubi_update_volume\(\) \{/ {
            in_update_wrapper = 1
            update_wrapper_definitions++
            next
        }
        in_update_wrapper && index($0, "dcent_ubi_semantic_identity_admit \"$_dcent_ubi_update_device\"") {
            semantic_admissions++
            semantic_admission_line = NR
        }
        in_update_wrapper && /^}/ {
            in_update_wrapper = 0
            next
        }
        in_update_wrapper && index($0, "dcent_ubi_volume_admit \"$_dcent_ubi_update_device\"") {
            node_admissions++
            node_admission_line = NR
        }
        /^[[:space:]]*ubiupdatevol/ {
            raw_writes++
            if (!in_update_wrapper) raw_writes_outside_wrapper++
            if (in_update_wrapper) wrapper_write_line = NR
        }
        /^[[:space:]]*if ! dcent_ubi_semantic_identity_admit 1 "\$INACTIVE_MTD"; then$/ {
            identity_admissions++
            identity_admission_line = NR
        }
        /^[[:space:]]*if ! dcent_ubi_attachment_require_absent \/sys\/class\/ubi 1 "\$INACTIVE_MTD"; then$/ {
            absence_admissions++
            absence_admission_line = NR
        }
        /^[[:space:]]*if ! dcent_ubi_attach_mtd "\$INACTIVE_MTD" 1( 2>\/dev\/null)?; then$/ {
            attaches++
            attach_line = NR
        }
        /^[[:space:]]*if ! dcent_ubi_update_volume 1 0 "\$KERNEL_SOURCE"; then$/ {
            kernel_writes++
            kernel_write_line = NR
        }
        /^[[:space:]]*if ! dcent_ubi_update_volume 1 1 "\$ROOTFS"; then$/ {
            rootfs_writes++
            rootfs_write_line = NR
        }
        END {
            exit !(identity_wrapper_definitions == 1 && raw_identity_admissions == 1 &&
                   update_wrapper_definitions == 1 && semantic_admissions == 1 &&
                   node_admissions == 1 &&
                   raw_writes == 1 && raw_writes_outside_wrapper == 0 &&
                   semantic_admission_line < node_admission_line &&
                   node_admission_line < wrapper_write_line &&
                   absence_admissions == 1 && attaches == 1 &&
                   absence_admission_line < attach_line &&
                   identity_admissions == 1 && kernel_writes == 1 &&
                   rootfs_writes == 1 &&
                   identity_admission_line < kernel_write_line &&
                   kernel_write_line < rootfs_write_line)
        }
    ' "$_caller"
}

make_absent_fixture
expect_success "unused ubi1 number and unattached inactive MTD are admitted" \
    admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubi1"
write_attr "$SYSFS_ROOT/ubi1/mtd_num" 9
expect_failure "occupied desired UBI number is refused even for another MTD" \
    admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubi2"
write_attr "$SYSFS_ROOT/ubi2/mtd_num" 8
expect_failure "inactive MTD attached under another UBI number is refused" \
    admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubi2"
write_attr "$SYSFS_ROOT/ubi2/mtd_num" 9
expect_success "unrelated attached UBI device does not block the inactive pair" \
    admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubi1_0"
expect_failure "residual desired-device volume entry is refused" \
    admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubi2_0"
expect_failure "orphan volume class entry is refused" admit_attachment_absence

make_absent_fixture
mkdir "$SYSFS_ROOT/ubigarbage"
expect_failure "unexpected UBI class entry is refused" admit_attachment_absence

make_absent_fixture
expect_failure "leading-zero desired UBI number is refused" \
    dcent_ubi_attachment_require_absent "$SYSFS_ROOT" 01 8

make_absent_fixture
expect_failure "leading-zero inactive MTD number is refused" \
    dcent_ubi_attachment_require_absent "$SYSFS_ROOT" 1 08

make_absent_fixture
mv "$SYSFS_ROOT/ubi0/mtd_num" "$WORK_ROOT/mtd-num"
ln -s "$WORK_ROOT/mtd-num" "$SYSFS_ROOT/ubi0/mtd_num"
expect_failure "symlinked existing-device MTD identity is refused" \
    admit_attachment_absence

make_fixture
expect_success "exact inactive-slot identity is admitted" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1/mtd_num" 7
expect_failure "wrong attached MTD is refused" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1/volumes_count" 2
expect_failure "reported missing volume is refused" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1/volumes_count" 4
expect_failure "reported extra volume is refused" admit_fixture

make_fixture
rm -rf "$SYSFS_ROOT/ubi1_2"
expect_failure "missing sysfs volume entry is refused" admit_fixture

make_fixture
mkdir "$SYSFS_ROOT/ubi1_3"
write_attr "$SYSFS_ROOT/ubi1_3/name" spare
write_attr "$SYSFS_ROOT/ubi1_3/type" dynamic
expect_failure "extra sysfs volume entry is refused despite stale count" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1_0/name" rootfs
write_attr "$SYSFS_ROOT/ubi1_1/name" kernel
expect_failure "permuted semantic volume names are refused" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1_1/type" mystery
expect_failure "unrecognized sysfs volume type is refused" admit_fixture

make_fixture
write_attr "$SYSFS_ROOT/ubi1_0/type" static
expect_failure "recognized but unexpected volume type is refused" admit_fixture

make_fixture
mv "$SYSFS_ROOT/ubi1_2/name" "$SYSFS_ROOT/rootfs-data-name"
ln -s "$SYSFS_ROOT/rootfs-data-name" "$SYSFS_ROOT/ubi1_2/name"
expect_failure "symlinked identity attribute is refused" admit_fixture

make_fixture
mv "$SYSFS_ROOT" "$WORK_ROOT/real-ubi"
ln -s "$WORK_ROOT/real-ubi" "$SYSFS_ROOT"
expect_failure "symlinked sysfs root is refused" admit_fixture

make_fixture
expect_failure "relative sysfs root is refused" \
    dcent_ubi_identity_admit relative/ubi 1 8 3 dynamic dynamic dynamic

make_fixture
expect_failure "nonnumeric UBI device input is refused" \
    dcent_ubi_identity_admit "$SYSFS_ROOT" '1/../../tmp' 8 3 dynamic dynamic dynamic

make_fixture
expect_failure "nonnumeric expected MTD input is refused" \
    dcent_ubi_identity_admit "$SYSFS_ROOT" 1 '8x' 3 dynamic dynamic dynamic

make_fixture
expect_failure "unsupported semantic volume count is refused" \
    dcent_ubi_identity_admit "$SYSFS_ROOT" 1 8 2 dynamic dynamic dynamic

make_fixture
expect_failure "unrecognized expected volume type is refused" \
    dcent_ubi_identity_admit "$SYSFS_ROOT" 1 8 3 dynamic compressed dynamic

expect_success "am1-s9 caller gates both volume writes by canonical identity" \
    caller_has_identity_gate \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s19j caller gates both volume writes by canonical identity" \
    caller_has_identity_gate \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s19pro caller gates both volume writes by canonical identity" \
    caller_has_identity_gate \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s17p caller gates both volume writes by canonical identity" \
    caller_has_identity_gate \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade"

printf '%s\n' "UBI identity tests: $tests assertions, $failures failures"
[ "$failures" -eq 0 ]
