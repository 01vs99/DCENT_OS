#!/bin/sh
#
# First-install capacity admission for am1-s9 (AM1-A Drop-1 route scoping
# follow-up; owner adjudication
#
# Option A, ratified 2026-09-15).
#
# The am1-s9 FIRST-INSTALL route is the standing stock-installer two-reboot
# transaction. Its phase-2 body creates HARD-SIZED UBI volumes before any
# payload write:
#   dcent-toolbox/src/dcent_toolbox/core/stage1_builder.py:640
#     ubimkvol /dev/ubi0 -N kernel -s 8MiB
#   dcent-toolbox/src/dcent_toolbox/core/stage1_builder.py:642
#     ubimkvol /dev/ubi0 -N rootfs -s 20MiB
# (The payload-derived rootfs_vol_size sizing in installer.py applies only
# to the UBI_CREATE_INACTIVE braiinsos A/B lane, not the stock transaction.)
# An oversized payload fails only at ubiupdatevol INSIDE phase 2
# (stage1_builder.py:650) — i.e. AFTER the phase-1 boot-chain flash and
# reboot — aborting the transaction mid-flight. A first-install-only
# package whose payload exceeds these capacities therefore has NO install
# route at all and must be refused at SEAL time (scripts/package_sysupgrade.sh)
# and at pre-flash WAIVER time (scripts/pre_flash_validate.sh --package-only).
#
# These are the stock-installer transaction's capacities, NOT live-sysupgrade
# geometry: scripts/lib/sysupgrade_zynq_geometry.sh (the operator-ratified
# self-update volume plan) is a different constraint set and is untouched.
# ubimkvol -s sizes are byte counts (UBI rounds reserved LEBs up), so a
# payload of exactly the volume size fits; admission uses plain -le.

AM1_S9_FIRST_INSTALL_KERNEL_MAX_BYTES=$((8 * 1024 * 1024))   # stage1_builder.py:640 ubimkvol kernel -s 8MiB
AM1_S9_FIRST_INSTALL_ROOTFS_MAX_BYTES=$((20 * 1024 * 1024))  # stage1_builder.py:642 ubimkvol rootfs -s 20MiB

dcent_am1_s9_first_install_capacity_fail()
{
    printf '%s\n' "am1-s9-first-install-capacity: ERROR: $*" >&2
    return 1
}

dcent_am1_s9_require_first_install_capacity()
{
    [ "$#" -eq 2 ] || {
        dcent_am1_s9_first_install_capacity_fail "first-install capacity proof requires kernel and rootfs byte sizes"
        return 1
    }
    _am1s9fi_kernel_size=$1
    _am1s9fi_rootfs_size=$2
    for _am1s9fi_payload_size in "$_am1s9fi_kernel_size" "$_am1s9fi_rootfs_size"; do
        case "$_am1s9fi_payload_size" in
            ''|*[!0-9]*|0)
                dcent_am1_s9_first_install_capacity_fail "payload size is not canonical decimal: $_am1s9fi_payload_size"
                return 1
                ;;
        esac
    done
    [ "$_am1s9fi_kernel_size" -le "$AM1_S9_FIRST_INSTALL_KERNEL_MAX_BYTES" ] || {
        dcent_am1_s9_first_install_capacity_fail \
            "first-install kernel payload exceeds the stock phase-2 hard volume ($_am1s9fi_kernel_size bytes > $AM1_S9_FIRST_INSTALL_KERNEL_MAX_BYTES bytes; ubimkvol kernel -s 8MiB, stage1_builder.py:640 — a larger payload would abort the two-reboot transaction mid-phase-2)"
        return 1
    }
    [ "$_am1s9fi_rootfs_size" -le "$AM1_S9_FIRST_INSTALL_ROOTFS_MAX_BYTES" ] || {
        dcent_am1_s9_first_install_capacity_fail \
            "first-install rootfs payload exceeds the stock phase-2 hard volume ($_am1s9fi_rootfs_size bytes > $AM1_S9_FIRST_INSTALL_ROOTFS_MAX_BYTES bytes; ubimkvol rootfs -s 20MiB, stage1_builder.py:642 — a larger payload would abort the two-reboot transaction mid-phase-2)"
        return 1
    }
    return 0
}
