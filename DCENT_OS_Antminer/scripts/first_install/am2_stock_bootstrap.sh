#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed recovery-image START40: recover authenticated unit inputs before SSH.
set -eu
umask 077
export LC_ALL=C
WORK=/tmp/dcent-stock-recovery
HELPER=/usr/libexec/dcent-am2-nand-window
fail() { echo "am2-stock-bootstrap: $*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }
bytes() { wc -c < "$1" | tr -d '[:space:]'; }
field() { awk -F= -v key="$2" '$1==key {n++; value=substr($0,length(key)+2)} END {if(n!=1) exit 1; print value}' "$1"; }
[ "$(id -u)" = 0 ] || fail root_required
[ ! -e "$WORK" ] || fail bootstrap_already_started
mkdir -m 700 "$WORK"
printf '/dev/mtd4 0x0 0x20000 0x20000 1\n/dev/mtd4 0x20000 0x20000 0x20000 1\n' > "$WORK/fw_env.config"
cp "$WORK/fw_env.config" /etc/fw_env.config
# The pinned vendor fw_env tool segfaults for both -l and --lock.
# Its default lock directory is volatile on this exact RAM-root source.
mkdir -p /var/lock || fail environment_lock_directory
fw_printenv -c /etc/fw_env.config > "$WORK/env" 2> "$WORK/env.errors" || fail environment_read
[ ! -s "$WORK/env.errors" ] || fail environment_diagnostics
ANCHOR=$(field "$WORK/env" dcent_stock_request_sha256) || fail request_anchor
case "$ANCHOR" in ''|*[!0-9a-f]*) fail request_anchor ;; esac
[ "${#ANCHOR}" = 64 ] || fail request_anchor
MAC=$(cat /sys/class/net/eth0/address)
"$HELPER" read dual10 migration "$WORK/migration.window" || fail migration_capture
head -c 512 "$WORK/migration.window" | tr '\000' '\n' > "$WORK/header"
[ "$(field "$WORK/header" schema)" = dcentos.am2-stock8-migration.v1 ] || fail migration_schema
[ "$(field "$WORK/header" mac)" = "$MAC" ] || fail migration_unit
[ "$(field "$WORK/header" request_sha256)" = "$ANCHOR" ] || fail migration_anchor
SIZE=$(field "$WORK/header" payload_size)
case "$SIZE" in ''|*[!0-9]*) fail archive_size ;; esac
[ "${#SIZE}" -le 8 ] && [ "$SIZE" -gt 0 ] && [ "$SIZE" -le 58720256 ] || fail archive_size
dd if="$WORK/migration.window" bs=1048576 skip=1 2>/dev/null | head -c "$SIZE" > "$WORK/payload.tar"
[ "$(bytes "$WORK/payload.tar")" = "$SIZE" ] || fail archive_short
[ "$(sha "$WORK/payload.tar")" = "$(field "$WORK/header" payload_sha256)" ] || fail archive_hash
rm "$WORK/migration.window"
tar -tf "$WORK/payload.tar" > "$WORK/members" || fail archive_invalid
printf '%s\n' am2-fabric.itb dcentrald.toml env.boot kernel network-static request rootfs ssh-authorized_keys ssh-host-ed25519 ssh-host-rsa > "$WORK/expected-members"
sort "$WORK/members" > "$WORK/sorted-members"
cmp "$WORK/expected-members" "$WORK/sorted-members" || fail archive_inventory
tar -tvf "$WORK/payload.tar" | awk 'substr($0,1,1)!="-" {exit 1}' || fail archive_nonregular_member
mkdir -m 700 "$WORK/inputs"
tar -xf "$WORK/payload.tar" -C "$WORK/inputs" || fail archive_extract
rm "$WORK/payload.tar"
REQUEST="$WORK/inputs/request"
[ "$(sha "$REQUEST")" = "$ANCHOR" ] || fail request_hash
[ "$(field "$REQUEST" schema)" = dcentos.am2-stock8-request.v1 ] || fail request_schema
[ "$(field "$REQUEST" source)" = stock-8part-single-slot ] || fail request_source
[ "$(field "$REQUEST" mac)" = "$MAC" ] || fail request_unit
[ "$(field "$REQUEST" hwid)" = "$(field "$WORK/env" miner_hwid)" ] || fail request_hardware_id
case "$(field "$REQUEST" board_target)" in am2-s19pro|am2-s19jpro-zynq|am2-s17p|am2-s17plus|am2-t17|am2-t17plus) ;; *) fail request_target ;; esac
for name in kernel rootfs am2-fabric.itb dcentrald.toml env.boot ssh-authorized_keys ssh-host-rsa ssh-host-ed25519 network-static; do
    path="$WORK/inputs/$name"
    [ -f "$path" ] && [ ! -L "$path" ] || fail input_not_regular
    key=$(printf '%s' "$name" | tr '.-' '__')_sha256
    [ "$(sha "$path")" = "$(field "$REQUEST" "$key")" ] || fail input_hash
done
[ -s "$WORK/inputs/ssh-authorized_keys" ] || fail operator_access_missing
[ -s "$WORK/inputs/ssh-host-rsa" ] || [ -s "$WORK/inputs/ssh-host-ed25519" ] || fail server_identity_missing
mkdir -p /etc/dropbear
chmod 700 /etc/dropbear
for type in rsa ed25519; do
    if [ -s "$WORK/inputs/ssh-host-$type" ]; then
        cp "$WORK/inputs/ssh-host-$type" "/etc/dropbear/dropbear_${type}_host_key"
        chmod 600 "/etc/dropbear/dropbear_${type}_host_key"
    fi
done
cp "$WORK/inputs/ssh-authorized_keys" /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
uci set 'dropbear.@dropbear[0].PasswordAuth=0'
uci set 'dropbear.@dropbear[0].RootPasswordAuth=0'
uci commit dropbear
printf '%s\n' "$ANCHOR" > "$WORK/ssh.ready"
echo 'state=stock_recovery_inputs_ready'
# The packaged Dropbear init refuses to start without ssh.ready and does not
# generate new server keys. START99 is the fixed DCENT writer, not a tar member.
