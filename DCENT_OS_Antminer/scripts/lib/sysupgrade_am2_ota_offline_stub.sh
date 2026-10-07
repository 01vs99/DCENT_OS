#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Offline-harness stub for the native AM2 OTA participant
# (usr/libexec/dcentos/am2-native-ota.sh).
#
# 2026-09-15 (C1 adjudication, brief 1): the am2 sysupgrade writers gained a
# hard OTA-participant requirement (05124af24) — they source the helper and
# call am2_ota_validate_package even in -T test mode, then prepare /
# write_fabric / commit_script / apply_environment around the slot flip. The
# deployed participant cannot run in the offline harness or the WSL guard
# suites: the signed FPGA payload chain (am2_ota_boot.py verify-payload on a
# real bitstream) and the dual10 window writer (am2-nand-window) exist only
# in the composed image. The writers' offline-override channel
# (DCENT_SYSUPGRADE_AM2_OTA_HELPER under DCENT_SYSUPGRADE_OFFLINE_HARNESS=1)
# is designed exactly for this: the deployed /usr/sbin/sysupgrade refuses
# every override (immutable-marker + realpath guard), so this stub can only
# ever be sourced by a non-deployed copy of the writer inside the offline
# proof.
#
# What this stub keeps REAL:
#   - am2_ota_prepare snapshots the complete pre-transaction U-Boot
#     environment (fw_printenv) into the transaction workspace, and
#     am2_ota_commit_script refuses to build the flip script unless that
#     snapshot still byte-matches the writer's own ENV_PRE_TEMP — the
#     "native source environment changed before the complete boot commit"
#     custody survives offline.
#   - am2_ota_apply_environment performs the same single
#     fw_setenv --script transaction as the deployed helper and classifies
#     the result by one complete CRC-valid readback (committed / unchanged /
#     indeterminate), never by the utility's exit status alone.
#   - The flip script itself (first_boot=yes, upgrade_stage=0,
#     firmware=$INACTIVE_FW) is byte-identical to the writer's own
#     pre-05124af24 fw_setenv script.
#
# What is deliberately offline-absent (documented, not silently skipped):
#   - am2_ota_validate_package performs no FPGA-signature verification: the
#     offline lab packages carry no bitstream/release signature. Upstream
#     archive admission (sysupgrade_archive_admission.sh +
#     sysupgrade-package-input.sh) has already validated tar/kernel identity
#     before the writer reaches this participant.
#   - am2_ota_write_fabric is a no-op: the nandsim layout has no dual10 FPGA
#     window. The fabric rung of _ORDERED_WRITER_CONTRACT stays covered by
#     the deployed helper on-device.

am2_ota_validate_package()
{
    # Offline packages carry no signed FPGA payload; structural package
    # admission already ran upstream. Fail closed if the writer somehow
    # reaches this stub without an admitted tar package context.
    [ "${DCENT_SYSUPGRADE_OFFLINE_HARNESS:-0}" = 1 ] || {
        echo "Error: offline AM2 OTA stub requires DCENT_SYSUPGRADE_OFFLINE_HARNESS=1" >&2
        return 1
    }
    return 0
}

am2_ota_prepare()
{
    [ "${DCENT_SYSUPGRADE_OFFLINE_HARNESS:-0}" = 1 ] || return 1
    AM2_OTA_PRE=$(dcent_sysupgrade_workspace_path am2-native-env.before) || return 1
    AM2_OTA_ERRORS=$(dcent_sysupgrade_workspace_path am2-native-env.errors) || return 1
    AM2_OTA_DIR=$(dcent_sysupgrade_workspace_path am2-native-boot) || return 1
    dcent_sysupgrade_workspace_require_absent "$AM2_OTA_PRE" || return 1
    dcent_sysupgrade_workspace_require_absent "$AM2_OTA_DIR" || return 1
    fw_printenv -c "$FW_ENV_CONFIG" >"$AM2_OTA_PRE" 2>"$AM2_OTA_ERRORS" || return 1
    [ ! -s "$AM2_OTA_ERRORS" ] || return 1
    mkdir -m 700 "$AM2_OTA_DIR" || return 1
    return 0
}

am2_ota_write_fabric()
{
    # No dual10 FPGA window exists in the nandsim layout; the fabric
    # write/readback rung is a deployed-image capability.
    [ -d "$AM2_OTA_DIR" ] || return 1
    return 0
}

am2_ota_commit_script()
{
    # Same pre-flip custody as the deployed helper: the environment the
    # transaction was prepared against must still byte-match the writer's
    # own pre-flip snapshot.
    cmp "$AM2_OTA_PRE" "$ENV_PRE_TEMP" || return 1
    cat >"$FW_SETENV_SCRIPT" <<EOF
first_boot=yes
upgrade_stage=0
firmware=${INACTIVE_FW}
EOF
}

_am2_ota_readback_committed()
{
    # One snapshot, U-Boot's own criterion, per-variable (order-independent):
    # exactly one firmware=$INACTIVE_FW, one upgrade_stage=0, one
    # first_boot=yes — the pre-05124af24 writer's post-flip check.
    _am2_fw=$(sed -n 's/^firmware=//p' "$1")
    _am2_stg=$(sed -n 's/^upgrade_stage=//p' "$1")
    _am2_first=$(sed -n 's/^first_boot=//p' "$1")
    [ "$(printf '%s\n' "$_am2_fw" | wc -l | tr -d ' ')" = 1 ] || return 1
    [ "$(printf '%s\n' "$_am2_stg" | wc -l | tr -d ' ')" = 1 ] || return 1
    [ "$(printf '%s\n' "$_am2_first" | wc -l | tr -d ' ')" = 1 ] || return 1
    [ "$_am2_fw" = "$INACTIVE_FW" ] && [ "$_am2_stg" = 0 ] && [ "$_am2_first" = yes ]
}

am2_ota_apply_environment()
{
    # The caller owns the update lock and has armed its environment journal.
    # A utility exit status cannot establish which redundant copy is durable;
    # classify one successful, warning-free complete readback against the
    # intended boot tuple, falling back to the prepared snapshot.
    AM2_OTA_ENV_RESULT=indeterminate
    AM2_OTA_ENV_WRITE_RC=0
    fw_setenv -c "$FW_ENV_CONFIG" --script "$FW_SETENV_SCRIPT" || AM2_OTA_ENV_WRITE_RC=$?
    rm -f "$FW_SETENV_SCRIPT" || return 1
    _am2_readback="$AM2_OTA_DIR/env.post-commit"
    _am2_errors="$AM2_OTA_DIR/env.post-commit.errors"
    fw_printenv -c "$FW_ENV_CONFIG" >"$_am2_readback" 2>"$_am2_errors" || return 1
    [ ! -s "$_am2_errors" ] || return 1
    if _am2_ota_readback_committed "$_am2_readback"; then
        AM2_OTA_ENV_RESULT=committed
        if [ "$AM2_OTA_ENV_WRITE_RC" -ne 0 ]; then
            echo "WARNING: fw_setenv returned an error; complete CRC-valid readback proves the new boot environment." >&2
        fi
        return 0
    fi
    if [ "$(cat "$_am2_readback")" = "$(cat "$AM2_OTA_PRE")" ]; then
        AM2_OTA_ENV_RESULT=unchanged
    fi
    return 1
}
