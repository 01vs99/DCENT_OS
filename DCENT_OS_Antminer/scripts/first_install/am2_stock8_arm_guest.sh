#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Runs ONLY as /init inside the disposable ARM virt fixture. No host disks/net.
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
        for path in /tmp/dcent-am2-stock8-*/env-probe/*.errors; do
            [ -f "$path" ] || continue
            echo "DIAGNOSTIC $path"
            cat "$path"
        done
    fi
    echo "DCENT_ARM_GUEST_EXIT=$rc"
    sync
    poweroff -f
    while :; do sleep 1; done
}
trap finish EXIT
grep -q 'dcent_i01_guest=stock8' /proc/cmdline
[ "$(tr '\000' '\n' < /proc/device-tree/compatible | head -n 1)" = 'linux,dummy-virt' ]
[ "$(cat /i01/FIXTURE)" = dcent-i01-arm-kernel-ordinary-identity-v1 ]
[ "$(uname -r)" = 6.1.0-52-armmp ]
insmod /lib/modules/6.1.0-52-armmp/kernel/drivers/mtd/nand/raw/nandsim.ko id_bytes=0x20,0xaa,0x00,0x15 overridesize=11 parts=320,256,64,16,112,128,448
awk 'NR>1 && $0 !~ /NAND simulator/ {exit 1} END {if(NR!=9) exit 1}' /proc/mtd
# Device bytes/geometry remain the real NAND simulator. Only target naming,
# MAC and RAM-root command line are fixture identities, scoped to this VM.
mount --bind /i01/proc-mtd /proc/mtd
mount --bind /i01/cmdline /proc/cmdline
mount --bind /i01/net /sys/class/net
i=0
while [ "$i" -lt 8 ]; do
    mount --bind "/i01/name$i" "/sys/class/mtd/mtd$i/name"
    i=$((i+1))
done
WORK=/tmp/dcent-am2-stock8-11111111111111111111111111111111
mkdir -m 700 "$WORK"
cp /i01/inputs/* "$WORK/"
chmod 700 "$WORK/am2-nand-window"
HELPER="$WORK/am2-nand-window"
"$HELPER" write stock8 transition-kernel /i01/original-kernel
"$HELPER" read stock8 transition-kernel /tmp/original-window
head -c 25165824 /dev/mtd0 | sha256sum > /tmp/boot-prefix.before
REQUEST_SHA=$(sha256sum "$WORK/request" | awk '{print $1}')
sh "$WORK/stage1.sh" preflight "$WORK" "$REQUEST_SHA"
sh "$WORK/stage1.sh" install "$WORK" "$REQUEST_SHA"
[ "$(cat "$WORK/state")" = kernel_committed ]
"$HELPER" verify-env stock8
"$HELPER" read stock8 transition-kernel /tmp/committed-window
head -c "$(wc -c < "$WORK/transition.itb")" /tmp/committed-window > /tmp/committed-fit
cmp "$WORK/transition.itb" /tmp/committed-fit
head -c 25165824 /dev/mtd0 | sha256sum > /tmp/boot-prefix.after
cmp /tmp/boot-prefix.before /tmp/boot-prefix.after
sh "$WORK/stage1.sh" restore-kernel "$WORK" "$REQUEST_SHA"
[ "$(cat "$WORK/state")" = stock_kernel_restored ]
"$HELPER" read stock8 transition-kernel /tmp/restored-window
cmp /tmp/original-window /tmp/restored-window
echo AM2_STOCK8_ARM_STAGE1_NANDSIM_OK
