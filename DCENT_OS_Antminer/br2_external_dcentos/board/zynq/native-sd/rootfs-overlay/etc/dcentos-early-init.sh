#!/bin/sh
# Dedicated native AM1 S9i/S9j and five AM2 SD roots. No NAND/UBI fallback.
# The unchanged native28 PID1 starts normal services only after this exits 0.
set -eu
case "$(cat /etc/dcentos/board_target)" in
    am1-s9i|am1-s9j|am2-s17p|am2-s17plus|am2-t17|am2-t17plus|am2-s19pro) ;;
    *) exit 80 ;;
esac
[ ! -e /etc/dcentos/external-media-ephemeral-root ] &&
    [ ! -L /etc/dcentos/external-media-ephemeral-root ] || exit 80
mount -t proc proc /proc 2>/dev/null || [ -r /proc/mounts ]
mount -t sysfs sysfs /sys 2>/dev/null || [ -d /sys/class ]
mount -t tmpfs -o size=1m,mode=0755 tmpfs /dev
mknod -m 600 /dev/console c 5 1
mknod -m 666 /dev/null c 1 3
mknod -m 666 /dev/zero c 1 5
mknod -m 666 /dev/tty c 5 0
mknod -m 666 /dev/ptmx c 5 2
mknod -m 444 /dev/random c 1 8
mknod -m 444 /dev/urandom c 1 9
mknod -m 600 /dev/mem c 1 1
mknod -m 600 /dev/kmsg c 1 11
mkdir -p /dev/pts /dev/shm
ln -s /proc/self/fd /dev/fd
ln -s fd/0 /dev/stdin
ln -s fd/1 /dev/stdout
ln -s fd/2 /dev/stderr
mount -t devpts -o gid=5,mode=620 devpts /dev/pts
mount -t tmpfs -o size=32m,mode=1777 tmpfs /tmp
mount -t tmpfs -o size=16m,mode=0755 tmpfs /run
mkdir -p /run/dcentos /run/lock /run/dropbear

# Only kernel-published native UIO/I2C, UART/watchdog and SD nodes. No raw
# MMIO, GPIO, PIC, FPGA or power operation is performed by this startup.
for native_node in /sys/class/uio/uio* /sys/class/i2c-dev/i2c-* \
    /sys/class/tty/ttyPS* /sys/class/watchdog/watchdog*; do
    [ -r "$native_node/dev" ] || continue
    native_name=${native_node##*/}
    native_numbers=$(cat "$native_node/dev")
    case "$native_numbers" in *[!0-9:]*|:*|*:) exit 81 ;; esac
    mknod -m 600 "/dev/$native_name" c "${native_numbers%:*}" "${native_numbers#*:}"
done
if [ ! -e /dev/watchdog ] && [ -r /sys/class/misc/watchdog/dev ]; then
    native_numbers=$(cat /sys/class/misc/watchdog/dev)
    case "$native_numbers" in *[!0-9:]*|:*|*:) exit 81 ;; esac
    mknod -m 600 /dev/watchdog c "${native_numbers%:*}" "${native_numbers#*:}"
elif [ ! -e /dev/watchdog ] && [ -e /dev/watchdog0 ]; then
    ln -s watchdog0 /dev/watchdog
fi
for native_name in ram0 mmcblk0 mmcblk0p1 mmcblk0p2 mmcblk0p3; do
    [ -r "/sys/class/block/$native_name/dev" ] || continue
    native_numbers=$(cat "/sys/class/block/$native_name/dev")
    case "$native_numbers" in *[!0-9:]*|:*|*:) exit 81 ;; esac
    mknod -m 600 "/dev/$native_name" b "${native_numbers%:*}" "${native_numbers#*:}"
done

# This exact helper validates actual boot/root/card/partition identities before
# the first data mount, then re-reads the mounted device and mount options.
/usr/bin/python3 /usr/libexec/dcentos/native-zynq-sd-storage.py
mkdir -p /data/dcent /data/keys/dropbear /data/config /data/logs
chmod 0700 /data/dcent /data/keys

# Both held kernels use a read-only SquashFS root. Volatile configuration
# copies avoid relying on overlayfs; durable API/configuration data stays on SD.
mkdir -p /run/native-sd-etc /run/native-sd-root
cp -a /etc/. /run/native-sd-etc/
cp -a /root/. /run/native-sd-root/
mount --bind /run/native-sd-etc /etc
mount --bind /run/native-sd-root /root
chmod 0700 /root
/usr/bin/python3 -I /usr/libexec/dcentos/native-zynq-sd-ssh.py
/usr/bin/python3 /usr/libexec/dcentos/native-zynq-sd-storage.py --verify
hostname "$(cat /etc/hostname)"
ip link set lo up
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
if [ -x /usr/sbin/seed-entropy ] && [ -e /data/keys/random-seed ]; then
    /usr/sbin/seed-entropy /data/keys/random-seed || true
fi
cat /proc/sys/kernel/random/boot_id > /run/dcentos/native-zynq-sd-ready
chmod 0600 /run/dcentos/native-zynq-sd-ready
echo "Native Zynq SD storage and writable configuration are ready."
