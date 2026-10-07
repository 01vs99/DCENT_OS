#!/bin/sh
# Mount-free, unprivileged tests for exact Zynq U-Boot env admission.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
HELPER=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/libexec/dcentos/sysupgrade-uboot-env-admission.sh
INSTALLED_CONFIG=$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/etc/fw_env.config
WORK_ROOT=${TMPDIR:-/tmp}/dcent-uboot-env-admission-test.$$
CONFIG=$WORK_ROOT/fw_env.config
PROC_MTD=$WORK_ROOT/proc-mtd
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
    _dcent_test_label=$1
    shift
    if "$@"; then pass "$_dcent_test_label"; else fail "$_dcent_test_label"; fi
}
expect_failure()
{
    _dcent_test_label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$_dcent_test_label (unexpected success)"
    else
        pass "$_dcent_test_label"
    fi
}

caller_has_uboot_env_contract()
{
    _dcent_test_caller=$1
    grep -Fq 'UBOOT_ENV_ADMISSION_HELPER="/usr/libexec/dcentos/sysupgrade-uboot-env-admission.sh"' \
        "$_dcent_test_caller" || return 1
    grep -Fq 'FW_ENV_CONFIG="/etc/fw_env.config"' "$_dcent_test_caller" || return 1
    grep -Fq 'UBOOT_ENV_PROC_MTD="/proc/mtd"' "$_dcent_test_caller" || return 1
    grep -Fq 'UBOOT_ENV_SYSFS_MTD_ROOT="/sys/class/mtd"' "$_dcent_test_caller" || return 1
    grep -Fq 'UBOOT_ENV_MTD4_DEVICE="/dev/mtd4"' "$_dcent_test_caller" || return 1
    grep -Fq 'DCENT_SYSUPGRADE_UBOOT_ENV_ADMISSION_HELPER' "$_dcent_test_caller" || return 1
    # Literal source-level contracts: expansion here would inspect host state.
    # shellcheck disable=SC2016
    grep -Fq '. "$UBOOT_ENV_ADMISSION_HELPER"' "$_dcent_test_caller" || return 1
    ! grep -Fq "grep -q '/dev/mtd4' /etc/fw_env.config" "$_dcent_test_caller" || return 1
    [ "$(grep -Fc 'if ! dcent_zynq_uboot_env_admit' "$_dcent_test_caller")" -eq 2 ] || return 1
    case "$_dcent_test_caller" in
        */zynq/am2-*/rootfs-overlay/usr/sbin/sysupgrade)
            # AM2's real complete-environment classifier is executed against
            # redundant files in test_am2_native_ota.py. Require its caller
            # join here while preserving the shared S9 inline writer checks.
            [ "$(grep -Fc '=$(fw_printenv -c "$FW_ENV_CONFIG"' "$_dcent_test_caller")" -eq 1 ] || return 1
            [ "$(grep -Fc 'if ! am2_ota_apply_environment; then' "$_dcent_test_caller")" -eq 1 ] || return 1
            grep -Fq '. "$AM2_OTA_HELPER"' "$_dcent_test_caller" || return 1
            grep -Fq 'am2_ota_commit_script || preflip_fail' "$_dcent_test_caller" || return 1
            grep -Fq 'ubiattach -m "$1" -d "$2" -O 2048 --max-beb-per1024=20' "$_dcent_test_caller" || return 1
            ;;
        *)
            # shellcheck disable=SC2016
            [ "$(grep -Fc '=$(fw_printenv -c "$FW_ENV_CONFIG"' "$_dcent_test_caller")" -eq 3 ] || return 1
            # shellcheck disable=SC2016
            [ "$(grep -Fc 'if ! fw_setenv -c "$FW_ENV_CONFIG" --script' "$_dcent_test_caller")" -eq 1 ] || return 1
            ;;
    esac
    awk '
        /^dcent_ubi_attach_mtd\(\) \{/ {
            in_attach_wrapper = 1
            attach_wrapper_definitions++
            next
        }
        in_attach_wrapper && /^}/ {
            in_attach_wrapper = 0
            next
        }
        in_attach_wrapper && /^[[:space:]]*dcent_ubi_node_admit \/sys\/class\/misc\/ubi_ctrl\/dev \/dev ubi_ctrl \|\| return 1$/ {
            control_node_admissions++
            control_node_admission_line = NR
        }
        /^[[:space:]]*ubiattach -m / {
            raw_attaches++
            if (!in_attach_wrapper) raw_attaches_outside_wrapper++
            if (in_attach_wrapper) wrapper_attach_line = NR
        }
        /\/bin\/sh "\$SESSION_LATCH_HELPER" admit-update/ { session = NR }
        /^[[:space:]]*if ! dcent_zynq_uboot_env_admit/ {
            admissions++
            if (admissions == 1) first_admission = NR
            if (admissions == 2) second_admission = NR
        }
        /^[[:space:]]*if ! dcent_ubi_attach_mtd "\$INACTIVE_MTD" 1( 2>\/dev\/null)?; then$/ && !first_mutation {
            first_mutation = NR
        }
        /_PRECHK=\$\(fw_printenv -c "\$FW_ENV_CONFIG"/ { first_env_read = NR }
        END {
            exit !(attach_wrapper_definitions == 1 &&
                   control_node_admissions == 1 && raw_attaches == 1 &&
                   raw_attaches_outside_wrapper == 0 &&
                   control_node_admission_line < wrapper_attach_line &&
                   session && first_admission && first_mutation &&
                   second_admission && first_env_read && admissions == 2 &&
                   session < first_admission && first_admission < first_mutation &&
                   second_admission < first_env_read)
        }
    ' "$_dcent_test_caller"
}

mkdir -p "$WORK_ROOT"

expect_success "exact config metadata is admitted" \
    _dcent_uboot_env_validate_config_metadata 1 0 0 0 0 644 1
expect_failure "non-regular config is refused" \
    _dcent_uboot_env_validate_config_metadata 0 0 0 0 0 644 1
expect_failure "symlinked config is refused" \
    _dcent_uboot_env_validate_config_metadata 1 1 0 0 0 644 1
expect_failure "symlinked config ancestor is refused" \
    _dcent_uboot_env_validate_config_metadata 1 0 1 0 0 644 1
expect_failure "non-root config owner is refused" \
    _dcent_uboot_env_validate_config_metadata 1 0 0 1000 0 644 1
expect_failure "non-root config group is refused" \
    _dcent_uboot_env_validate_config_metadata 1 0 0 0 1000 644 1
expect_failure "group-writable config is refused" \
    _dcent_uboot_env_validate_config_metadata 1 0 0 0 0 664 1
expect_failure "hard-linked config is refused" \
    _dcent_uboot_env_validate_config_metadata 1 0 0 0 0 644 2

write_canonical_config()
{
    printf '%s\n%s\n' \
        '/dev/mtd4 0x00000 0x20000 0x20000 1' \
        '/dev/mtd4 0x20000 0x20000 0x20000 1' >"$CONFIG"
}

write_canonical_config
expect_success "byte-exact redundant config is admitted" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
expect_success "installed fw_env.config is the exact 72-byte parser input" \
    _dcent_uboot_env_validate_config_content_path "$INSTALLED_CONFIG"
printf '\tprintable ASCII\n' >"$CONFIG"
expect_success "ASCII validator permits tab, LF, and printable bytes" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf 'forbidden\001byte\n' >"$CONFIG"
expect_failure "ASCII validator refuses a C0 control byte" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf 'forbidden\000byte\n' >"$CONFIG"
expect_failure "ASCII validator refuses NUL" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf 'forbidden\rbyte\n' >"$CONFIG"
expect_failure "ASCII validator refuses carriage return" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf 'forbidden\177byte\n' >"$CONFIG"
expect_failure "ASCII validator refuses DEL" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf 'forbidden\303\251byte\n' >"$CONFIG"
expect_failure "ASCII validator refuses UTF-8 multibyte input" \
    _dcent_uboot_env_validate_ascii_path "$CONFIG"
printf '%s\n%s\n' \
    '/dev/mtd4 0x20000 0x20000 0x20000 1' \
    '/dev/mtd4 0x00000 0x20000 0x20000 1' >"$CONFIG"
expect_failure "reordered redundant records are refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
write_canonical_config
printf '%s\n' '/dev/mtd4 0x40000 0x20000 0x20000 1' >>"$CONFIG"
expect_failure "third environment record is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
printf '%s\n' '/dev/mtd4 0x00000 0x20000 0x20000 1' >"$CONFIG"
expect_failure "single-copy environment config is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
write_canonical_config
printf '\r\n' >>"$CONFIG"
expect_failure "trailing CRLF content is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
printf '%s\n%s' \
    '/dev/mtd4 0x00000 0x20000 0x20000 1' \
    '/dev/mtd4 0x20000 0x20000 0x20000 1' >"$CONFIG"
expect_failure "missing final newline is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
printf '%s\n%s\n' \
    '/dev/mtd5 0x00000 0x20000 0x20000 1' \
    '/dev/mtd5 0x20000 0x20000 0x20000 1' >"$CONFIG"
expect_failure "wrong environment device is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"
printf '%s\n%s\n' \
    '/dev/mtd4 0x00000 0x10000 0x10000 1' \
    '/dev/mtd4 0x10000 0x10000 0x10000 1' >"$CONFIG"
expect_failure "wrong redundant geometry is refused" \
    _dcent_uboot_env_validate_config_content_path "$CONFIG"

write_canonical_proc_mtd()
{
    printf '%s\n' \
        'dev:    size   erasesize  name' \
        'mtd0: 00500000 00020000 "BOOT.bin-env-dts-kernel"' \
        'mtd4: 00080000 00020000 "uboot_env"' \
        'mtd7: 06400000 00020000 "firmware1"' >"$PROC_MTD"
}

write_canonical_proc_mtd
expect_success "exact kernel mtd4 record is admitted" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD"
sed 's/00080000/00040000/' "$PROC_MTD" >"$PROC_MTD.changed"
expect_failure "wrong mtd4 size is refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"
sed 's/mtd4: 00080000 00020000/mtd4: 00080000 00010000/' \
    "$PROC_MTD" >"$PROC_MTD.changed"
expect_failure "wrong mtd4 erase size is refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"
sed 's/"uboot_env"/"environment"/' "$PROC_MTD" >"$PROC_MTD.changed"
expect_failure "wrong mtd4 name is refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"
cp "$PROC_MTD" "$PROC_MTD.changed"
printf '%s\n' 'mtd4: 00080000 00020000 "uboot_env"' >>"$PROC_MTD.changed"
expect_failure "duplicate mtd4 record is refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"
grep -v '^mtd4:' "$PROC_MTD" >"$PROC_MTD.changed"
expect_failure "missing mtd4 record is refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"
sed 's/"uboot_env"$/"uboot_env" unexpected/' "$PROC_MTD" >"$PROC_MTD.changed"
expect_failure "extra mtd4 fields are refused" \
    _dcent_uboot_env_validate_proc_mtd_path "$PROC_MTD.changed"

expect_success "exact sysfs identity is admitted" \
    _dcent_uboot_env_validate_sysfs_identity uboot_env 524288 131072 90:8
expect_failure "wrong sysfs name is refused" \
    _dcent_uboot_env_validate_sysfs_identity environment 524288 131072 90:8
expect_failure "wrong sysfs size is refused" \
    _dcent_uboot_env_validate_sysfs_identity uboot_env 262144 131072 90:8
expect_failure "wrong sysfs erase size is refused" \
    _dcent_uboot_env_validate_sysfs_identity uboot_env 524288 65536 90:8
expect_failure "malformed sysfs device number is refused" \
    _dcent_uboot_env_validate_sysfs_identity uboot_env 524288 131072 90:8:1
expect_failure "nonnumeric sysfs device number is refused" \
    _dcent_uboot_env_validate_sysfs_identity uboot_env 524288 131072 mtd:8

expect_success "exact character-device metadata matches sysfs rdev" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 600 1 5a 8 90:8
expect_failure "non-character device is refused" \
    _dcent_uboot_env_validate_device_metadata 0 0 0 0 600 1 5a 8 90:8
expect_failure "symlinked device node is refused" \
    _dcent_uboot_env_validate_device_metadata 1 1 0 0 600 1 5a 8 90:8
expect_failure "non-root device owner is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 1 0 600 1 5a 8 90:8
expect_failure "non-root device group is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 1 600 1 5a 8 90:8
expect_failure "permissive device mode is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 660 1 5a 8 90:8
expect_failure "hard-linked device node is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 600 2 5a 8 90:8
expect_failure "wrong device major is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 600 1 59 8 90:8
expect_failure "wrong device minor is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 600 1 5a a 90:8
expect_failure "malformed stat major is refused" \
    _dcent_uboot_env_validate_device_metadata 1 0 0 0 600 1 '5a;id' 8 90:8
expect_success "four absolute evidence-source paths are admitted by the path contract" \
    _dcent_uboot_env_validate_evidence_paths /etc/fw_env.config /proc/mtd /sys/class/mtd /dev/mtd4
expect_failure "relative config evidence is refused" \
    _dcent_uboot_env_validate_evidence_paths etc/fw_env.config /proc/mtd /sys/class/mtd /dev/mtd4
expect_failure "relative proc evidence is refused" \
    _dcent_uboot_env_validate_evidence_paths /etc/fw_env.config proc/mtd /sys/class/mtd /dev/mtd4
expect_failure "relative sysfs evidence is refused" \
    _dcent_uboot_env_validate_evidence_paths /etc/fw_env.config /proc/mtd sys/class/mtd /dev/mtd4
expect_failure "relative device evidence is refused" \
    _dcent_uboot_env_validate_evidence_paths /etc/fw_env.config /proc/mtd /sys/class/mtd dev/mtd4
expect_failure "filesystem root cannot be an evidence source" \
    _dcent_uboot_env_validate_evidence_paths /etc/fw_env.config /proc/mtd / /dev/mtd4
expect_failure "public admission rejects the wrong argument count" \
    dcent_zynq_uboot_env_admit "$WORK_ROOT"

expect_success "am1-s9 caller binds and orders exact environment admission" \
    caller_has_uboot_env_contract \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s19j caller binds and orders exact environment admission" \
    caller_has_uboot_env_contract \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s19pro caller binds and orders exact environment admission" \
    caller_has_uboot_env_contract \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/usr/sbin/sysupgrade"
expect_success "am2-s17pro caller binds and orders exact environment admission" \
    caller_has_uboot_env_contract \
    "$PROJECT_ROOT/br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/usr/sbin/sysupgrade"
for target in am2-s17plus am2-t17 am2-t17plus; do
    expect_success "$target caller binds and orders exact environment admission" \
        caller_has_uboot_env_contract \
        "$PROJECT_ROOT/br2_external_dcentos/board/zynq/$target/rootfs-overlay/usr/sbin/sysupgrade"
done

if [ "$failures" -ne 0 ]; then
    printf '\nU-Boot environment admission tests failed: %s/%s failed\n' \
        "$failures" "$tests" >&2
    exit 1
fi
printf '\nU-Boot environment admission tests passed: %s assertions\n' "$tests"
