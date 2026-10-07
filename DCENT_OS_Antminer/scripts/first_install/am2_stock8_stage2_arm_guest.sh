#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Only /init in the isolated ARM virt fixture. No host disks or networking.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
exec </dev/console >/dev/console 2>&1
finish() {
    rc=$?; trap - EXIT
    if [ "$rc" != 0 ]; then
        for path in /tmp/dcent-stock-recovery/*.errors /tmp/dcent-stock-recovery/env-probe/errors; do
            [ -f "$path" ] || continue
            echo "DIAGNOSTIC $path"; cat "$path"
        done
    fi
    echo "DCENT_ARM_GUEST_EXIT=$rc"
    sync
    poweroff -f
    while :; do sleep 1; done
}
trap finish EXIT
grep -q 'dcent_i01_guest=stock8-stage2' /proc/cmdline
[ "$(tr '\000' '\n' < /proc/device-tree/compatible | head -n 1)" = 'linux,dummy-virt' ]
[ "$(cat /i01/FIXTURE)" = dcent-i01-arm-kernel-ordinary-identity-v1 ]
[ "$(uname -r)" = 6.1.0-52-armmp ]
insmod /lib/modules/6.1.0-52-armmp/kernel/drivers/mtd/nand/raw/nandsim.ko id_bytes=0x20,0xaa,0x00,0x15 overridesize=11 parts=64,96,16,16,4,4,696,456,456
awk 'NR>1 && $0 !~ /NAND simulator/ {exit 1} END {if(NR!=11) exit 1}' /proc/mtd
mount --bind /i01/proc-mtd /proc/mtd
mount --bind /i01/cmdline /proc/cmdline
mount --bind /i01/net /sys/class/net
i=0
while [ "$i" -lt 10 ]; do
    mount --bind "/i01/name$i" "/sys/class/mtd/mtd$i/name"
    i=$((i+1))
done
insmod /lib/modules/6.1.0-52-armmp/kernel/lib/crc16.ko
insmod /lib/modules/6.1.0-52-armmp/kernel/drivers/mtd/ubi/ubi.ko
insmod /lib/modules/6.1.0-52-armmp/kernel/lib/zstd/zstd_compress.ko
insmod /lib/modules/6.1.0-52-armmp/kernel/crypto/zstd.ko
insmod /lib/modules/6.1.0-52-armmp/kernel/crypto/deflate.ko
insmod /lib/modules/6.1.0-52-armmp/kernel/fs/ubifs/ubifs.ko
HELPER=/usr/libexec/dcent-am2-nand-window
if [ -f /i01/stock-BOOT.bin ]; then
    # Fixture initialization, before production scripts: seed the original
    # source BOOT prefix once. Production helper makes this region read-only.
    nandwrite -p /dev/mtd0 /i01/stock-BOOT.bin
fi
"$HELPER" write dual10 migration /i01/migration.container
"$HELPER" write dual10 kernel-backup /i01/kernel-backup.container
mkdir -p /var/lock
printf '/dev/mtd4 0x0 0x20000 0x20000 1\n/dev/mtd4 0x20000 0x20000 0x20000 1\n' > /etc/fw_env.config
# Fixture initialization uses only the exercised fw_setenv implementation.
fw_printenv -c /etc/fw_env.config > /tmp/defaults 2> /tmp/blank-env.errors
awk -F= '{print $1 "="}' /tmp/defaults > /tmp/env.initialize
cat /i01/env.defaults >> /tmp/env.initialize
fw_setenv -c /etc/fw_env.config --script /tmp/env.initialize
fw_setenv -c /etc/fw_env.config dcent_fixture_second_copy yes
"$HELPER" verify-env dual10
sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd3 /dev/mtd5 /dev/mtd9 > /tmp/preserved.before
/usr/sbin/dcent-stock-bootstrap
[ "$(cat /tmp/dcent-stock-recovery/ssh.ready)" = "$(cat /i01/anchor)" ]
cmp /i01/inputs/ssh-host-rsa /etc/dropbear/dropbear_rsa_host_key
cmp /i01/inputs/ssh-authorized_keys /etc/dropbear/authorized_keys
/usr/sbin/dcent-stock-stage2 auto-install
[ "$(cat /tmp/dcent-stock-recovery/state)" = committed ]
"$HELPER" verify-env dual10
fw_printenv -c /etc/fw_env.config > /tmp/env.committed
grep -qx 'firmware=1' /tmp/env.committed
grep -qx 'dcent_stock_stage=committed' /tmp/env.committed
sha256sum /dev/mtd2 /dev/mtd7 > /tmp/native.before
# Returning to recovery after native boot failure must not format again.
/usr/sbin/dcent-stock-stage2 auto-install > /tmp/reentry.receipt
grep -qx 'state=recovery_after_native_boot_failure' /tmp/reentry.receipt
sha256sum /dev/mtd2 /dev/mtd7 > /tmp/native.after
cmp /tmp/native.before /tmp/native.after
sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd3 /dev/mtd5 /dev/mtd9 > /tmp/preserved.after
cmp /tmp/preserved.before /tmp/preserved.after
if [ -d /i01/restore ]; then
    RESTORE=/tmp/dcent-am2-stock-restore-22222222222222222222222222222222
    mkdir -m 700 "$RESTORE"
    cp /i01/restore/* "$RESTORE/"
    ANCHOR=$(sha256sum "$RESTORE/request" | awk '{print $1}')
    sh "$RESTORE/restore.sh" preflight "$RESTORE" "$ANCHOR"
    sh "$RESTORE/restore.sh" begin "$RESTORE" "$ANCHOR"
    if /usr/sbin/dcent-stock-stage2 auto-install; then echo 'restore interlock failed'; exit 1; fi
    while read -r name size; do
        if [ "$name" != transition-kernel ] && grep -qx "$name=matches" "$RESTORE/census"; then continue; fi
        CHUNK="$RESTORE/chunk-33333333333333333333333333333333"
        mkdir -m 700 "$CHUNK"
        if [ "$name" = transition-kernel ]; then
            cp /i01/original-kernel "$CHUNK/payload"
            sh "$RESTORE/restore.sh" commit "$RESTORE" "$ANCHOR" "$name" "$CHUNK/payload"
        else
            head -c "$size" /dev/zero | tr '\000' '\377' > "$CHUNK/payload"
            sh "$RESTORE/restore.sh" restore "$RESTORE" "$ANCHOR" "$name" "$CHUNK/payload"
        fi
    done < /i01/restore-windows
    [ "$(cat "$RESTORE/state")" = stock_restored ]
    "$HELPER" read dual10 transition-kernel /tmp/restored-kernel
    cmp /i01/original-kernel /tmp/restored-kernel
    "$HELPER" verify-env-keys dual10 "$RESTORE/env.restore"
    echo AM2_STOCK8_ARM_FULL_RESTORE_NANDSIM_OK
    echo AM2_STOCK8_ARM_STAGE2_NANDSIM_OK
    exit 0
fi
/usr/sbin/dcent-stock-stage2 restore-stock-kernel
"$HELPER" read dual10 transition-kernel /tmp/restored-kernel
cmp /i01/original-kernel /tmp/restored-kernel
echo AM2_STOCK8_ARM_STAGE2_NANDSIM_OK
