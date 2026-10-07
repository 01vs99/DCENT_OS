#!/bin/sh
# Isolated ARM virt fixture only; real NAND/UBI/tools, simulated boot identity.
export PATH=/i01/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mkdir -p /run/lock
exec </dev/console >/dev/console 2>&1
finish() {
    rc=$?; trap - EXIT
    echo "DCENT_ARM_GUEST_EXIT=$rc"
    sync
    poweroff -f
    while :; do sleep 1; done
}
trap finish EXIT
grep -q 'dcent_i01_guest=native-ota' /proc/cmdline
[ "$(tr '\000' '\n' < /proc/device-tree/compatible | head -n 1)" = linux,dummy-virt ]
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
HELPER=/usr/libexec/dcentos/am2-nand-window
# Fixture initialization only: source native slot and empty inactive UBI.
"$HELPER" write dual10 fpga1 /i01/am2-fabric.itb
mkdir -p /var/lock /data
printf '/dev/mtd4 0x00000 0x20000 0x20000 1\n/dev/mtd4 0x20000 0x20000 0x20000 1\n' > /etc/fw_env.config
chmod 644 /etc/fw_env.config
fw_setenv -c /etc/fw_env.config -f /i01/env.defaults --script /i01/env.defaults
fw_setenv -c /etc/fw_env.config dcent_fixture_second_copy yes
"$HELPER" verify-env dual10
ubiformat /dev/mtd7 -q -y -O 2048
ubiattach -m 7 -d 0 -O 2048 --max-beb-per1024=20
for row in '0 kernel 2920448' '1 rootfs 22728704' '2 rootfs_data 26664960'; do
    set -- $row
    ubimkvol /dev/ubi0 -n "$1" -N "$2" -s "$3" -t dynamic
done
ubiupdatevol /dev/ubi0_0 /i01/kernel
ubiupdatevol /dev/ubi0_1 /i01/rootfs
mount -t ubifs -o rw ubi0:rootfs_data /data
mkdir -m 700 /data/dcent /data/keys /data/network /data/vendor-first-install
printf '[mining]\nenabled = false\n' > /data/dcentrald.toml
printf 'IP=192.0.2.10\nMASK=255.255.255.0\n' > /data/network/static
printf 'original recovery custody\n' > /data/vendor-first-install/receipt
ubiformat /dev/mtd8 -q -y -O 2048
mount --bind /i01/cmdline-native1 /proc/cmdline
sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2 /dev/mtd5 /dev/mtd6 /dev/mtd9 > /tmp/preserved.before
fw_printenv -c /etc/fw_env.config > /tmp/env.original
# Native read-only environment verification must not grant active FPGA writes.
"$HELPER" verify-env dual10
if "$HELPER" write dual10 fpga1 /i01/am2-fabric.itb; then
    echo 'ERROR: native active-FPGA write was admitted' >&2; exit 1
fi
export DCENT_SYSUPGRADE_OFFLINE_HARNESS=1
export DCENT_SYSUPGRADE_OFFLINE_MARKER=/i01/offline-marker
# This is the production script at a non-deployed path; all environment and
# UBI tools remain real, and helper/device/metadata paths retain defaults.
sh /i01/sysupgrade -T --stop-miner /i01/native-ota.tar
# Fixture browser-job custody is created before the real updater migrates /data.
# The standalone worker itself has separate process/FD/binding tests.
export DCENT_UPDATE_JOB_ID=550e8400-e29b-41d4-a716-446655440000
export DCENT_UPDATE_JOB_PACKAGE_SHA256=$(sha256sum /i01/native-ota.tar | awk '{print $1}')
export DCENT_UPDATE_JOB_SOURCE_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path('/data/dcent/update-jobs')
root.mkdir(mode=0o700)
job = root / os.environ['DCENT_UPDATE_JOB_ID']
job.mkdir(mode=0o700)
status = {'schema': 1, 'job_id': job.name,
          'package_sha256': os.environ['DCENT_UPDATE_JOB_PACKAGE_SHA256'],
          'source_boot_id': os.environ['DCENT_UPDATE_JOB_SOURCE_BOOT_ID'],
          'state': 'reboot_pending'}
p = job / 'status.json'
p.write_text(json.dumps(status))
p.chmod(0o600)
PY
sh /i01/sysupgrade -f /i01/native-ota.tar
fw_printenv -c /etc/fw_env.config > /tmp/env.updated
grep -qx firmware=2 /tmp/env.updated
grep -qx upgrade_stage=0 /tmp/env.updated
"$HELPER" verify-env dual10
sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2 /dev/mtd5 /dev/mtd6 /dev/mtd9 > /tmp/preserved.after
cmp /tmp/preserved.before /tmp/preserved.after
TRANSACTION=$(find /data/dcent/ota-native -mindepth 1 -maxdepth 1 -type d | head -n 1)
[ -n "$TRANSACTION" ]
cp "$TRANSACTION/receipt.json" /tmp/receipt.json
python3 /usr/libexec/dcentos/am2_ota_boot.py verify-environment --receipt /tmp/receipt.json --environment /tmp/env.updated --state after
echo AM2_NATIVE_ARM_OTA_WRITE_NANDSIM_OK
# Explicit fixture transition: no physical/U-Boot boot claim. Preserve the
# completed first-boot update journal, then model the new boot's volatile /run.
cp -a /run/dcentos-sysupgrade.lock /i01/retained-update-lock
rm /run/dcentos-sysupgrade.lock/owner
rmdir /run/dcentos-sysupgrade.lock
umount /data
ubidetach -d 0
ubiattach -m 8 -d 0 -O 2048 --max-beb-per1024=20
mount -t ubifs -o rw ubi0:rootfs_data /data
mount --bind /i01/cmdline-native2 /proc/cmdline
printf 'first_boot=\nupgrade_stage=\n' > /tmp/fixture-boot-commit
fw_setenv -c /etc/fw_env.config --script /tmp/fixture-boot-commit
fw_printenv -c /etc/fw_env.config > /tmp/fixture-env-committed
unset DCENT_SYSUPGRADE_OFFLINE_HARNESS DCENT_SYSUPGRADE_OFFLINE_MARKER
TRANSACTION_NAME=${TRANSACTION##*/}
cmp /tmp/receipt.json "/data/dcent/ota-native/$TRANSACTION_NAME/receipt.json"
grep -qx IP=192.0.2.10 /data/network/static
grep -qx 'original recovery custody' /data/vendor-first-install/receipt
# Exercise the deployed S99 read-only observation hook against real CRC-valid
# env copies. Only the new kernel boot UUID is fixture-simulated here.
JOB=/data/dcent/update-jobs/$DCENT_UPDATE_JOB_ID
cp "$JOB/status.json" /tmp/job-status.original
sh /etc/init.d/S99upgrade start
[ ! -e "$JOB/boot-observation.json" ]  # Source boot cannot qualify its own update.
printf '550e8400-e29b-41d4-a716-446655440001\n' > /i01/new-boot-id
mount --bind /i01/new-boot-id /proc/sys/kernel/random/boot_id
sh /etc/init.d/S99upgrade start
python3 - <<'PY'
import json, os
from pathlib import Path
job = Path('/data/dcent/update-jobs') / os.environ['DCENT_UPDATE_JOB_ID']
observation = json.loads((job/'boot-observation.json').read_text())
assert observation['job_id'] == job.name
assert observation['package_sha256'] == os.environ['DCENT_UPDATE_JOB_PACKAGE_SHA256']
assert observation['source_boot_id'] == os.environ['DCENT_UPDATE_JOB_SOURCE_BOOT_ID']
assert observation['observed_boot_id'] == '550e8400-e29b-41d4-a716-446655440001'
assert observation['boot_environment_committed'] is True
assert observation['physical_hashing_verified'] is False
assert observation['firmware'] == 2
assert len(observation['receipt_sha256']) == 64
assert (job/'boot-observation.json').stat().st_mode & 0o777 == 0o600
PY
cmp "$JOB/status.json" /tmp/job-status.original
fw_printenv -c /etc/fw_env.config > /tmp/env.observed
cmp /tmp/env.observed /tmp/fixture-env-committed
echo AM2_NATIVE_ARM_UPDATE_BOOT_OBSERVATION_NANDSIM_OK
/usr/sbin/dcent-am2-ota-rollback "$TRANSACTION_NAME"
fw_printenv -c /etc/fw_env.config > /tmp/env.restored
cmp /tmp/env.original /tmp/env.restored
"$HELPER" verify-env dual10
echo AM2_NATIVE_ARM_OTA_ROLLBACK_NANDSIM_OK
