#!/bin/sh
# Exact C43 native SD: read-only ext2 root and UUID-bound writable SD data.
# No NAND/UBI nodes, attach, mount, environment update or FPGA/GPIO writes.
set -eu
case "$(cat /etc/dcentos/board_target)" in am1-s9se|am1-s9k) ;; *) exit 80 ;; esac
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
hostname "$(cat /etc/hostname)"

# Create only the native controller's required char nodes and SD block nodes.
for dcent_node in /sys/class/tty/ttyPS* /sys/class/watchdog/watchdog*; do
    [ -r "$dcent_node/dev" ] || continue
    dcent_name=${dcent_node##*/}
    dcent_numbers=$(cat "$dcent_node/dev")
    mknod -m 600 "/dev/$dcent_name" c "${dcent_numbers%:*}" "${dcent_numbers#*:}"
done
# Kernel4.6 may expose only the legacy misc watchdog class.
if [ ! -e /dev/watchdog ] && [ -r /sys/class/misc/watchdog/dev ]; then
    dcent_numbers=$(cat /sys/class/misc/watchdog/dev)
    mknod -m 600 /dev/watchdog c "${dcent_numbers%:*}" "${dcent_numbers#*:}"
elif [ ! -e /dev/watchdog ] && [ -e /dev/watchdog0 ]; then
    ln -s watchdog0 /dev/watchdog
fi
for dcent_name in mmcblk0 mmcblk0p1 mmcblk0p2 mmcblk0p3; do
    [ -r "/sys/class/block/$dcent_name/dev" ] || continue
    dcent_numbers=$(cat "/sys/class/block/$dcent_name/dev")
    mknod -m 600 "/dev/$dcent_name" b "${dcent_numbers%:*}" "${dcent_numbers#*:}"
done
ip link set lo up
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

dcent_root_uuid=$(cat /etc/dcentos/c43-root-uuid)
dcent_data_uuid=$(cat /etc/dcentos/c43-data-uuid)
# Fixed ext2/ext4 superblock UUID field (1024+104), read-only. The pinned
# BusyBox has dd/hexdump; a standalone blkid binary is not assumed.
dcent_ext_uuid() {
    dd if="$1" bs=1 skip=1128 count=16 2>/dev/null | hexdump -v -e '1/1 "%02x"'
}
[ "$(dcent_ext_uuid /dev/mmcblk0p2)" = "$(printf '%s' "$dcent_root_uuid" | tr -d '-')" ] || exit 81
[ "$(dcent_ext_uuid /dev/mmcblk0p3)" = "$(printf '%s' "$dcent_data_uuid" | tr -d '-')" ] || exit 81
awk '$2 == "/" && $3 == "ext2" { n++; c=split($4,a,","); for(i=1;i<=c;i++) if(a[i]=="ro") r++ }
     END { exit (n==1 && r==1) ? 0 : 1 }' /proc/mounts || exit 81
mount -t ext4 -o rw,nodev,nosuid /dev/mmcblk0p3 /data || exit 82
mkdir -p /data/dcent /data/keys/dropbear /data/config /data/logs
chmod 0700 /data/dcent /data/keys

# Donor kernel has no overlayfs. A small tmpfs copy makes ordinary config,
# resolv.conf and host-key files writable; durable API data stays on SD /data.
mkdir -p /run/c43-etc /run/c43-root
cp -a /etc/. /run/c43-etc/
cp -a /root/. /run/c43-root/
mount --bind /run/c43-etc /etc
mount --bind /run/c43-root /root
chmod 0700 /root
if [ -x /usr/sbin/seed-entropy ] && [ -e /data/keys/random-seed ]; then
    /usr/sbin/seed-entropy /data/keys/random-seed || true
fi
printf '%s\n' "$dcent_data_uuid" > /run/dcentos/c43-sd-data-ready
echo "C43 native SD storage and device nodes ready."
