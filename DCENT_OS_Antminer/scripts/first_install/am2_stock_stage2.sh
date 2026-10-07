#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed RAM-recovery writer. Never executes a command from the migration tar.
set -eu
umask 077
export LC_ALL=C
MODE=${1:-}
WORK=/tmp/dcent-stock-recovery
INPUT="$WORK/inputs"
REQUEST="$INPUT/request"
HELPER=/usr/libexec/dcent-am2-nand-window
STATE=ready
MOUNTED=0
ATTACHED=0
case "$MODE" in auto-install|install|restore-stock-kernel|status) ;; *) exit 64 ;; esac
fail() { echo "am2-stock-stage2: $*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
bytes() { wc -c < "$1" | tr -d '[:space:]'; }
field() { awk -F= -v key="$2" '$1==key {n++; value=substr($0,length(key)+2)} END {if(n!=1) exit 1; print value}' "$1"; }
request() { field "$REQUEST" "$1"; }
state() { STATE=$1; printf '%s\n' "$STATE" > "$WORK/state.next"; sync; mv "$WORK/state.next" "$WORK/state"; sync; }
receipt() { printf 'schema=dcentos.am2-stock8-stage2-receipt.v1\nrequest_sha256=%s\nstate=%s\nreboot_performed=false\n' "${ANCHOR:-unknown}" "$STATE"; }
cleanup() {
    rc=$?; trap - EXIT HUP INT TERM
    if [ "$MOUNTED" = 1 ]; then umount "$WORK/data" || rc=1; fi
    if [ "$ATTACHED" = 1 ]; then ubidetach -d "$UBI" || rc=1; fi
    receipt; exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
[ "$(id -u)" = 0 ] && [ ! -L "$WORK" ] && [ "$(stat -c '%u:%g:%a' "$WORK")" = 0:0:700 ] || fail private_root_workspace
[ -f "$WORK/ssh.ready" ] && [ -f "$REQUEST" ] && [ ! -L "$REQUEST" ] || fail bootstrap_required
ANCHOR=$(cat "$WORK/ssh.ready")
[ "$(sha "$REQUEST")" = "$ANCHOR" ] || fail request_changed
if [ -f "$WORK/state" ]; then STATE=$(cat "$WORK/state"); fi
if [ "$MODE" = status ]; then exit 0; fi
fresh_file() {
    [ ! -L "$1" ] || fail private_file_symlink
    if [ -e "$1" ]; then [ -f "$1" ] || fail private_file_identity; rm "$1"; fi
}
LOCK=/tmp/dcent-am2-stock8.lock
if [ ! -e "$LOCK" ]; then mkdir -m 700 "$LOCK" || fail lock_create; fi
[ ! -L "$LOCK" ] && [ "$(stat -c '%u:%g:%a' "$LOCK")" = 0:0:700 ] || fail lock_owner
[ ! -L "$LOCK/mutex" ] || fail lock_symlink
if [ ! -e "$LOCK/mutex" ]; then (set -C; : > "$LOCK/mutex") || fail lock_create; fi
exec 9> "$LOCK/mutex"
"$HELPER" lock || fail concurrent_writer
"$HELPER" check dual10 transition-kernel || fail exact_recovery_map
[ "$(cat /sys/class/net/eth0/address)" = "$(request mac)" ] || fail unit_changed
# The pinned vendor fw_env tool segfaults for both -l and --lock.
# Its default lock directory is volatile on this exact RAM-root source.
mkdir -p /var/lock || fail environment_lock_directory
fw_printenv -c /etc/fw_env.config > "$WORK/env.current" 2> "$WORK/env.errors" || fail environment_read
[ ! -s "$WORK/env.errors" ] || fail environment_diagnostics
[ "$(field "$WORK/env.current" dcent_stock_request_sha256)" = "$ANCHOR" ] || fail environment_anchor
[ "$(field "$WORK/env.current" miner_hwid)" = "$(request hwid)" ] || fail hardware_identity
[ "$(field "$WORK/env.current" dcent_stock_stage)" != restoring ] || fail full_stock_restore_in_progress
if [ "$MODE" = auto-install ]; then
    if [ "$(field "$WORK/env.current" dcent_stock_stage)" = committed ]; then
        STATE=recovery_after_native_boot_failure
        exit 0
    fi
    [ "$(field "$WORK/env.current" dcent_stock_stage)" = recovery_prepared ] || fail recovery_phase
    MODE=install
fi
for name in kernel rootfs am2-fabric.itb dcentrald.toml env.boot ssh-authorized_keys ssh-host-rsa ssh-host-ed25519 network-static; do
    [ -f "$INPUT/$name" ] && [ ! -L "$INPUT/$name" ] || fail input_not_regular
    key=$(printf '%s' "$name" | tr '.-' '__')_sha256
    [ "$(sha "$INPUT/$name")" = "$(request "$key")" ] || fail input_changed
done
[ "$(bytes "$INPUT/kernel")" -gt 0 ] && [ "$(bytes "$INPUT/kernel")" -le 2920448 ] || fail kernel_window
[ "$(bytes "$INPUT/rootfs")" -gt 0 ] && [ "$(bytes "$INPUT/rootfs")" -le 22728704 ] || fail rootfs_window
[ "$(bytes "$INPUT/am2-fabric.itb")" -gt 0 ] && [ "$(bytes "$INPUT/am2-fabric.itb")" -le 2097152 ] || fail fpga_window

# Prove the immutable recovery image's fw_setenv batch behavior on ordinary
# records before any actual MTD change. No raw environment write is attempted.
if [ -e "$WORK/env-probe" ]; then
    [ -d "$WORK/env-probe" ] && [ ! -L "$WORK/env-probe" ] || fail probe_directory
    for name in record env config change errors after; do fresh_file "$WORK/env-probe/$name"; done
    rmdir "$WORK/env-probe" || fail unexpected_probe_file
fi
mkdir "$WORK/env-probe"
{ printf '\111\022\155\072\001dcent_probe=before\000dcent_remove=present\000\000'; head -c 4050 /dev/zero; } > "$WORK/env-probe/record"
[ "$(sha "$WORK/env-probe/record")" = 939a269c744df26e5a808eb1ceb4cd889e022f0e277f834986c21a8f7cc9d403 ] || fail probe_template
cat "$WORK/env-probe/record" "$WORK/env-probe/record" > "$WORK/env-probe/env"
printf '%s 0x0 0x1000 0x1000\n%s 0x1000 0x1000 0x1000\n' "$WORK/env-probe/env" "$WORK/env-probe/env" > "$WORK/env-probe/config"
printf 'dcent_probe=after\ndcent_remove=\n' > "$WORK/env-probe/change"
fw_setenv -c "$WORK/env-probe/config" --script "$WORK/env-probe/change" 2> "$WORK/env-probe/errors" || fail probe_write
[ ! -s "$WORK/env-probe/errors" ] || fail probe_diagnostics
fw_printenv -c "$WORK/env-probe/config" > "$WORK/env-probe/after" 2> "$WORK/env-probe/errors" || fail probe_read
[ ! -s "$WORK/env-probe/errors" ] && [ "$(cat "$WORK/env-probe/after")" = dcent_probe=after ] || fail probe_readback
rm "$WORK/env-probe/record" "$WORK/env-probe/env" "$WORK/env-probe/config" "$WORK/env-probe/change" "$WORK/env-probe/errors" "$WORK/env-probe/after"
rmdir "$WORK/env-probe"

# Read and verify the retained original kernel before replacing any firmware.
# These dd/head/gzip operations use private ordinary files only.
BACKUP_SIZE=$(request kernel_backup_size)
case "$BACKUP_SIZE" in ''|*[!0-9]*) fail backup_size ;; esac
[ "${#BACKUP_SIZE}" -le 8 ] && [ "$BACKUP_SIZE" -gt 1048576 ] && [ "$BACKUP_SIZE" -le 13631488 ] || fail backup_size
fresh_file "$WORK/kernel-backup.window"
"$HELPER" read dual10 kernel-backup "$WORK/kernel-backup.window" || fail backup_capture
head -c "$BACKUP_SIZE" "$WORK/kernel-backup.window" > "$WORK/kernel-backup.container"
[ "$(bytes "$WORK/kernel-backup.container")" = "$BACKUP_SIZE" ] && [ "$(sha "$WORK/kernel-backup.container")" = "$(request kernel_backup_sha256)" ] || fail backup_readback
dd if="$WORK/kernel-backup.container" bs=1048576 skip=1 2>/dev/null > "$WORK/kernel-backup.gz"
gzip -dc "$WORK/kernel-backup.gz" > "$WORK/original-kernel" || fail backup_decompression
[ "$(bytes "$WORK/original-kernel")" = 8388608 ] && [ "$(sha "$WORK/original-kernel")" = "$(request original_kernel_sha256)" ] || fail original_kernel_readback
rm "$WORK/kernel-backup.window" "$WORK/kernel-backup.container" "$WORK/kernel-backup.gz"
if [ "$MODE" = restore-stock-kernel ]; then
    state stock_kernel_restore_pending
    "$HELPER" write dual10 transition-kernel "$WORK/original-kernel" || fail stock_kernel_restore
    state stock_boot_window_restored
    exit 0
fi
case "$STATE" in
    committed) exit 0 ;;
    env_commit_pending) fail indeterminate_boot_commit_use_status ;;
    stock_kernel_restore_pending|stock_boot_window_restored) fail stock_restore_in_progress ;;
    ready|writing|payloads_verified) ;;
    *) fail unknown_stage ;;
esac
for node in /sys/class/ubi/ubi[0-9]*; do
    [ -f "$node/mtd_num" ] || continue
    [ "$(cat "$node/mtd_num")" != 7 ] || fail destination_already_attached
done
UBI=0
while [ -e "/sys/class/ubi/ubi$UBI" ]; do UBI=$((UBI + 1)); [ "$UBI" -lt 32 ] || fail ubi_index; done
cp "$WORK/env.current" "$WORK/env.before"
state writing
"$HELPER" write dual10 fpga1 "$INPUT/am2-fabric.itb" || fail fpga_write
ubiformat /dev/mtd7 -y -O 2048 || fail firmware_format
ubiattach -m 7 -d "$UBI" -O 2048 --max-beb-per1024=20 || fail firmware_attach
ATTACHED=1
[ "$(cat "/sys/class/ubi/ubi$UBI/mtd_num")" = 7 ] && [ "$(cat "/sys/class/ubi/ubi$UBI/eraseblock_size")" = 126976 ] && [ "$(cat "/sys/class/ubi/ubi$UBI/avail_eraseblocks")" = 412 ] || fail firmware_geometry
for row in '0 kernel 2920448' '1 rootfs 22728704' '2 rootfs_data 26664960'; do
    set -- $row
    ubimkvol "/dev/ubi$UBI" -n "$1" -N "$2" -s "$3" -t dynamic || fail volume_create
done
for row in 'kernel 0' 'rootfs 1'; do
    set -- $row
    ubiupdatevol "/dev/ubi${UBI}_$2" "$INPUT/$1" || fail image_write
    head -c "$(bytes "$INPUT/$1")" "/dev/ubi${UBI}_$2" > "$WORK/readback"
    cmp "$INPUT/$1" "$WORK/readback" || fail image_readback
    [ "$(cat "/sys/class/ubi/ubi${UBI}_$2/corrupted")" = 0 ] || fail image_corrupted
done
if [ -e "$WORK/data" ]; then
    [ -d "$WORK/data" ] && [ ! -L "$WORK/data" ] || fail data_directory
    rmdir "$WORK/data" || fail data_mount_not_released
fi
mkdir "$WORK/data"
mount -t ubifs -o rw "ubi$UBI:rootfs_data" "$WORK/data" || fail data_mount
MOUNTED=1
mkdir -p "$WORK/data/vendor-first-install" "$WORK/data/keys/dropbear" "$WORK/data/dcent" "$WORK/data/network"
cp "$REQUEST" "$WORK/data/vendor-first-install/stock-request"
cp "$WORK/env.before" "$WORK/data/vendor-first-install/stock-env.before"
cp "$INPUT/dcentrald.toml" "$WORK/data/dcentrald.toml"
cp "$INPUT/ssh-authorized_keys" "$WORK/data/dcent/authorized_keys"
if [ -s "$INPUT/network-static" ]; then cp "$INPUT/network-static" "$WORK/data/network/static"; fi
: > "$WORK/data/dcent/.ssh-enabled"
for kind in rsa ed25519; do
    if [ -s "$INPUT/ssh-host-$kind" ]; then cp "$INPUT/ssh-host-$kind" "$WORK/data/keys/dropbear/dropbear_${kind}_host_key"; fi
done
sync
umount "$WORK/data" || fail data_unmount
MOUNTED=0
mount -t ubifs -o ro "ubi$UBI:rootfs_data" "$WORK/data" || fail data_remount
MOUNTED=1
cmp "$REQUEST" "$WORK/data/vendor-first-install/stock-request" || fail persisted_request
cmp "$INPUT/dcentrald.toml" "$WORK/data/dcentrald.toml" || fail persisted_config
cmp "$INPUT/ssh-authorized_keys" "$WORK/data/dcent/authorized_keys" || fail persisted_client_key
if [ -s "$INPUT/network-static" ]; then cmp "$INPUT/network-static" "$WORK/data/network/static" || fail persisted_network; fi
for kind in rsa ed25519; do
    if [ -s "$INPUT/ssh-host-$kind" ]; then cmp "$INPUT/ssh-host-$kind" "$WORK/data/keys/dropbear/dropbear_${kind}_host_key" || fail persisted_host_key; fi
done
umount "$WORK/data" || fail data_unmount
MOUNTED=0
rmdir "$WORK/data"
ubidetach -d "$UBI" || fail firmware_detach
ATTACHED=0
state payloads_verified
fw_printenv -c /etc/fw_env.config > "$WORK/env.current" 2> "$WORK/env.errors" || fail environment_read
[ ! -s "$WORK/env.errors" ] && cmp "$WORK/env.before" "$WORK/env.current" || fail environment_changed
awk '{sub(/ /,"="); print}' "$INPUT/env.boot" > "$WORK/env.change"
printf 'first_boot=yes\nupgrade_stage=0\nfirmware=1\ndcent_stock_stage=committed\n' >> "$WORK/env.change"
state env_commit_pending
fw_setenv -c /etc/fw_env.config --script "$WORK/env.change" || fail boot_commit_indeterminate
fw_printenv -c /etc/fw_env.config > "$WORK/env.after" 2> "$WORK/env.errors" || fail boot_commit_read
[ ! -s "$WORK/env.errors" ] || fail boot_commit_diagnostics
while IFS='=' read -r key value; do [ "$(field "$WORK/env.after" "$key")" = "$value" ] || fail boot_commit_readback; done < "$WORK/env.change"
state committed
# Reboot is an explicit Toolbox/operator action. restore-stock-kernel restores
# the original boot window; full stock reserve cleanup is a separate phase.
