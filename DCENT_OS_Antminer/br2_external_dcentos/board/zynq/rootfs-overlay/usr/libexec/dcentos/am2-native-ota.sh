#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Native AM2 FPGA + complete boot tuple participant in the existing updater.

am2_ota_probe_environment_tools()
{
    _am2_probe=$(dcent_sysupgrade_workspace_path am2-env-abi-probe) || return 1
    mkdir -m 700 "$_am2_probe" || return 1
    # Ordinary files only. This proves the installed utility's real batch
    # assignment/deletion ABI before any MTD mutation.
    { printf '\111\022\155\072\001dcent_probe=before\000dcent_remove=present\000\000'; head -c 4050 /dev/zero; } > "$_am2_probe/record"
    [ "$(sha256sum "$_am2_probe/record" | awk '{print $1}')" = 939a269c744df26e5a808eb1ceb4cd889e022f0e277f834986c21a8f7cc9d403 ] || return 1
    cat "$_am2_probe/record" "$_am2_probe/record" > "$_am2_probe/env" || return 1
    printf '%s 0x0 0x1000 0x1000\n%s 0x1000 0x1000 0x1000\n' "$_am2_probe/env" "$_am2_probe/env" > "$_am2_probe/config"
    printf 'dcent_probe=after\ndcent_remove=\n' > "$_am2_probe/change"
    mkdir -p /var/lock || return 1
    fw_setenv -c "$_am2_probe/config" --script "$_am2_probe/change" 2> "$_am2_probe/errors" || return 1
    [ ! -s "$_am2_probe/errors" ] || return 1
    fw_printenv -c "$_am2_probe/config" > "$_am2_probe/after" 2> "$_am2_probe/errors" || return 1
    [ ! -s "$_am2_probe/errors" ] && [ "$(cat "$_am2_probe/after")" = dcent_probe=after ]
}

am2_ota_validate_package()
{
    AM2_OTA_TOOL=/usr/libexec/dcentos/am2_ota_boot.py
    AM2_OTA_WRITER=/usr/libexec/dcentos/am2-nand-window
    # The caller already checks the immutable offline marker and refuses these
    # overrides at the deployed /usr/sbin/sysupgrade path.
    if [ "${DCENT_SYSUPGRADE_OFFLINE_HARNESS:-0}" = 1 ]; then
        AM2_OTA_TOOL=${DCENT_SYSUPGRADE_AM2_OTA_TOOL:-$AM2_OTA_TOOL}
        AM2_OTA_WRITER=${DCENT_SYSUPGRADE_AM2_OTA_WRITER:-$AM2_OTA_WRITER}
    fi
    [ "$PACKAGE_INPUT_IS_TAR" = 1 ] && [ -n "$PACKAGE_KERNEL" ] &&
        [ -f "$PACKAGE_BITSTREAM" ] && [ -f "$PACKAGE_SIG" ] || {
        echo "Error: native AM2 OTA requires a signed kernel/rootfs/FPGA package" >&2; return 1;
    }
    python3 "$AM2_OTA_TOOL" verify-payload "$PACKAGE_BITSTREAM"
}

am2_ota_prepare()
{
    [ -r "$AM2_OTA_TOOL" ] && [ -x "$AM2_OTA_WRITER" ] || {
        echo "Error: native AM2 OTA tools are absent from this image" >&2; return 1;
    }
    am2_ota_probe_environment_tools || return 1
    AM2_OTA_PRE=$(dcent_sysupgrade_workspace_path am2-native-env.before) || return 1
    AM2_OTA_ERRORS=$(dcent_sysupgrade_workspace_path am2-native-env.errors) || return 1
    AM2_OTA_DIR=$(dcent_sysupgrade_workspace_path am2-native-boot) || return 1
    dcent_sysupgrade_workspace_require_absent "$AM2_OTA_PRE" || return 1
    fw_printenv -c "$FW_ENV_CONFIG" > "$AM2_OTA_PRE" 2> "$AM2_OTA_ERRORS" || return 1
    [ ! -s "$AM2_OTA_ERRORS" ] || return 1
    "$AM2_OTA_WRITER" check dual10 "fpga$INACTIVE_FW" || return 1
    python3 "$AM2_OTA_TOOL" prepare --bitstream "$PACKAGE_BITSTREAM" \
        --active-fpga "/dev/mtd$((CURRENT_FW + 1))" --environment "$AM2_OTA_PRE" \
        --package-sha256 "$AM2_OTA_PACKAGE_SHA256" \
        --cmdline "$PROC_CMDLINE_PATH" --current "$CURRENT_FW" --output "$AM2_OTA_DIR" || return 1
}

am2_ota_write_fabric()
{
    [ -d "$AM2_OTA_DIR" ] && [ ! -L "$AM2_OTA_DIR" ] || return 1
    # The fixed-window helper validates real MTD geometry, rejects every bad
    # block before erasing, writes only the inactive2MiB FPGA, and reads it back.
    "$AM2_OTA_WRITER" write dual10 "fpga$INACTIVE_FW" "$AM2_OTA_DIR/am2-fabric.itb" || return 1
    AM2_OTA_SAVE="$PERSIST_SOURCE_ROOT/dcent/ota-native/${AM2_OTA_DIR##*/}-${DCENT_SYSUPGRADE_WORKSPACE##*/}"
    [ ! -e "$AM2_OTA_SAVE" ] && [ ! -L "$AM2_OTA_SAVE" ] || return 1
    for _am2_dir in "$PERSIST_SOURCE_ROOT/dcent" "$PERSIST_SOURCE_ROOT/dcent/ota-native"; do
        [ ! -L "$_am2_dir" ] || return 1
        if [ ! -e "$_am2_dir" ]; then mkdir -m 700 "$_am2_dir" || return 1; fi
        [ -d "$_am2_dir" ] && [ "$(stat -c '%u' "$_am2_dir")" = 0 ] || return 1
    done
    mkdir -m 700 "$AM2_OTA_SAVE" || return 1
    cp "$AM2_OTA_DIR/receipt.json" "$AM2_OTA_DIR/env.rollback" "$AM2_OTA_SAVE/" || return 1
    cp "$AM2_OTA_PRE" "$AM2_OTA_SAVE/env.before" || return 1
    chmod 600 "$AM2_OTA_SAVE/receipt.json" "$AM2_OTA_SAVE/env.rollback" "$AM2_OTA_SAVE/env.before" || return 1
    sync || return 1
    cmp "$AM2_OTA_DIR/receipt.json" "$AM2_OTA_SAVE/receipt.json" &&
        cmp "$AM2_OTA_DIR/env.rollback" "$AM2_OTA_SAVE/env.rollback" &&
        cmp "$AM2_OTA_PRE" "$AM2_OTA_SAVE/env.before"
    # Existing persistent-state stage/verify copies this complete dcent subtree
    # to the inactive data volume before the final environment commit.
}

am2_ota_commit_script()
{
    # Bind the initial source boot tuple to the snapshot immediately before
    # commit, including unrelated keys that must remain untouched.
    cmp "$AM2_OTA_PRE" "$ENV_PRE_TEMP" || return 1
    cp "$AM2_OTA_DIR/env.change" "$FW_SETENV_SCRIPT"
}

am2_ota_verify_snapshot()
{
    _am2_state=$1
    _am2_snapshot=$2
    python3 "$AM2_OTA_TOOL" verify-environment --receipt "$AM2_OTA_DIR/receipt.json" \
        --environment "$_am2_snapshot" --state "$_am2_state"
}

am2_ota_apply_environment()
{
    # The caller owns the update lock and has armed its environment journal.
    # A utility exit status cannot establish which redundant copy is durable.
    # Classify one successful, warning-free complete readback against the
    # authenticated transaction, including every unrelated factory key.
    AM2_OTA_ENV_RESULT=indeterminate
    AM2_OTA_ENV_WRITE_RC=0
    fw_setenv -c "$FW_ENV_CONFIG" --script "$FW_SETENV_SCRIPT" || AM2_OTA_ENV_WRITE_RC=$?
    rm -f "$FW_SETENV_SCRIPT" || return 1
    _am2_readback="$AM2_OTA_DIR/env.post-commit"
    _am2_errors="$AM2_OTA_DIR/env.post-commit.errors"
    fw_printenv -c "$FW_ENV_CONFIG" > "$_am2_readback" 2> "$_am2_errors" || return 1
    [ ! -s "$_am2_errors" ] || return 1
    if am2_ota_verify_snapshot after "$_am2_readback" 2> "$AM2_OTA_DIR/env.verify-after.errors"; then
        AM2_OTA_ENV_RESULT=committed
        if [ "$AM2_OTA_ENV_WRITE_RC" -ne 0 ]; then
            echo "WARNING: fw_setenv returned an error; complete CRC-valid readback proves the new boot environment." >&2
        fi
        return 0
    fi
    if am2_ota_verify_snapshot before "$_am2_readback" 2> "$AM2_OTA_DIR/env.verify-before.errors"; then
        AM2_OTA_ENV_RESULT=unchanged
    fi
    return 1
}
