#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Run only in a disposable virtme guest. Canonical target shell, real kernel
# nandsim/UBI/libubootenv; simulated identity and native guest dependency tools.
# This proves storage transactions, not target ARM dependency closure or boot.
set -euo pipefail
WORK=${1:-}
STAGE1=${2:-}
WRITER=${3:-}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
LAYOUT=${DCENT_AM2_NANDSIM_LAYOUT:-canonical}
case "$LAYOUT" in canonical|blank|vendor) ;; *) exit 64 ;; esac
[[ "$WORK" == /tmp/dcent-am2-nandsim-* && ! -e "$WORK" ]] || exit 64
[[ -f "$STAGE1" && ! -L "$STAGE1" ]] || exit 64
[[ -f "$WRITER" && ! -L "$WRITER" ]] || exit 64
[[ "${DCENT_DISPOSABLE_VIRTME:-}" == am2-first-install-v1 ]] || exit 64
[[ $(id -u) == 0 ]] || exit 64
grep -Eq 'QEMU|KVM|Standard PC' /sys/class/dmi/id/product_name || exit 64
# Refuse a guest with any pre-existing MTD device: never borrow host hardware.
[[ ! -e /proc/mtd ]] || [[ $(awk 'END {print NR}' /proc/mtd) == 1 ]] || exit 64
for tool in modprobe ubiattach ubidetach ubiupdatevol ubiformat ubimkvol mkenvimage nanddump nandwrite flash_erase fw_printenv fw_setenv mount chroot python3; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 77; }
done
mkdir -m 700 "$WORK"
mount --make-rprivate /
modprobe nandsim id_bytes=0x20,0xaa,0x00,0x15 overridesize=11 parts=64,96,16,16,4,4,696,456,456
awk 'NR>1 && $0 !~ /NAND simulator/ {exit 1} END {if(NR!=11) exit 1}' /proc/mtd
modprobe ubi
modprobe ubifs
# Exact 412-LEB AM2 accounting needs the verified no-fastmap pair loaded by
# the caller; a stock Ubuntu fastmap build cannot produce the same geometry.
[[ ! -e /sys/module/ubi/parameters/fm_autoconvert ]] || { echo "AM2 needs no-fastmap module pair" >&2; exit 77; }
for node in /sys/class/mtd/mtd[0-9]*; do
    [[ -f "$node/dev" ]] || continue
    name=${node##*/}; IFS=: read -r major minor < "$node/dev"
    [[ -c /dev/$name ]] || mknod "/dev/$name" c "$major" "$minor"
done
ROOT="$WORK/root"
mkdir -p "$ROOT"/{bin,usr,lib,lib64,dev,proc,sys,etc,tmp,overlay} "$WORK/identity/net/eth0"
mount --bind "$ROOT" "$ROOT"
for path in bin usr lib lib64 dev proc sys; do
    [[ -d /$path ]] || continue
    mount --rbind "/$path" "$ROOT/$path"
done
# Ubuntu's native awk is an alternatives symlink; preserve this guest-only
# userspace dependency without importing any target identity/configuration.
mkdir "$ROOT/etc/alternatives"
mount --bind /etc/alternatives "$ROOT/etc/alternatives"
cleanup() {
    rc=$?
    trap - EXIT
    umount -R "$ROOT" 2>/dev/null || true
    ubidetach -d 1 2>/dev/null || true
    ubidetach -d 0 2>/dev/null || true
    modprobe -r nandsim 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
cp /proc/mtd "$WORK/physical-proc-mtd"
printf '02:00:00:00:00:01\n' > "$WORK/identity/net/eth0/address"
printf 'console=ttyPS0 ubi.mtd=7 root=ubi0:rootfs\n' > "$WORK/identity/cmdline"
python3 - "$WORK/identity/proc-mtd" <<'PY'
import sys
parts=[('boot',8),('boot-failover',12),('fpga1',2),('fpga2',2),('uboot_env',.5),('miner_cfg',.5),('recovery',87),('firmware1',57),('firmware2',57),('factory',30)]
with open(sys.argv[1],'w') as f:
 f.write('dev:    size   erasesize  name\n')
 for i,(name,mib) in enumerate(parts):f.write(f'mtd{i}: {int(mib*1048576):08x} 00020000 "{name}"\n')
from pathlib import Path
for i,(name,_) in enumerate(parts):Path(sys.argv[1]).with_name(f'name{i}').write_text(name+'\n')
PY
for name in size erasesize; do
    [[ $(cat /sys/class/mtd/mtd4/$name) == $(case "$name" in size) echo 524288;; *) echo 131072;; esac) ]]
done
mount --bind "$WORK/identity/proc-mtd" "$ROOT/proc/mtd"
mount --bind "$WORK/identity/cmdline" "$ROOT/proc/cmdline"
mount --bind "$WORK/identity/net" "$ROOT/sys/class/net"
for i in {0..9}; do mount --bind "$WORK/identity/name$i" "$ROOT/sys/class/mtd/mtd$i/name"; done
printf 'fixture vendor version\n' > "$ROOT/etc/bos_version"
printf '/dev/mtd4 0x00000 0x20000 0x20000\n/dev/mtd4 0x20000 0x20000 0x20000\n' > "$ROOT/etc/fw_env.config"
printf 'firmware=1\nminer_hwid=fixture123\nfactory_serial=preserve-me\nnandboot=run vendor_boot\n' > "$WORK/env.txt"
mkenvimage -r -s 0x20000 -o "$WORK/env.copy" "$WORK/env.txt"
cat "$WORK/env.copy" "$WORK/env.copy" > "$WORK/env.seed"
# Only harness initialization seeds the disposable simulator. The transaction
# and rollback themselves always use the real fw_setenv utility.
flash_erase /dev/mtd4 0 0 >/dev/null
nandwrite -p /dev/mtd4 "$WORK/env.seed" >/dev/null
chroot "$ROOT" fw_printenv -c /etc/fw_env.config > "$WORK/env.before"
for index in 7 8; do
    if [[ "$index" == 8 && "$LAYOUT" == blank ]]; then continue; fi
    ubiformat "/dev/mtd$index" -y -O 2048 >/dev/null
    ubiattach -m "$index" -d 0 -O 2048 --max-beb-per1024=20 >/dev/null
    [[ $(cat /sys/class/ubi/ubi0/eraseblock_size) == 126976 ]]
    [[ $(cat /sys/class/ubi/ubi0/avail_eraseblocks) == 412 ]]
    for row in '0 kernel 2920448' '1 rootfs 22728704' '2 rootfs_data 26664960'; do
        read -r id name size <<< "$row"
        if [[ "$index" == 8 && "$LAYOUT" == vendor ]]; then
            case "$id" in 1) size=$((202 * 126976));; 2) size=$((187 * 126976));; esac
        fi
        ubimkvol /dev/ubi0 -n "$id" -N "$name" -s "$size" >/dev/null
    done
    ubidetach -d 0
done
nanddump -q --omitoob --bb=padbad /dev/mtd7 | sha256sum > "$WORK/active.before"
nanddump -q --omitoob --bb=padbad /dev/mtd9 | sha256sum > "$WORK/factory.before"
nanddump -q --omitoob --bb=padbad /dev/mtd2 | sha256sum > "$WORK/fpga-active.before"
TX="$ROOT/tmp/transaction"
mkdir -m 700 "$TX"
cp "$STAGE1" "$TX/stage1.sh"
cp "$WRITER" "$TX/am2-nand-window"
printf 'original vendor configuration\n' > "$ROOT/overlay/pools.conf"
python3 - "$TX" "$ROOT" "$SCRIPT_DIR" "$WORK/env.before" <<'PY'
from pathlib import Path
import hashlib,sys
p=Path(sys.argv[1]);root=Path(sys.argv[2])
sys.path.insert(0,sys.argv[3])
from prepare_am2_fabric_boot import nand_boot_environment
# Image bootability is checked by host capsule tests; this harness targets
# exact write/readback sizes without claiming to boot an emulated miner.
(p/'kernel').write_bytes(b'nandsim kernel payload\n'*8192)
(p/'rootfs').write_bytes(b'hsqs'+b'nandsim rootfs payload\n'*65536)
(p/'dcentrald.toml').write_bytes(b'[mining]\nenabled=false\nmodel="s19jpro"\n')
(p/'ssh-host-rsa').write_bytes(b'')
(p/'ssh-host-ed25519').write_bytes(b'ordinary storage fixture server key\n')
(p/'ssh-authorized_keys').write_bytes(b'ordinary storage fixture authorized key\n')
(p/'am2-fabric.itb').write_bytes(b'FPGA storage fixture\n'*65536)
(p/'env.boot').write_text(''.join(f'{key} {value}\n' for key,value in sorted(nand_boot_environment(2,'run vendor_boot').items())))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
request={'schema':'dcentos.am2-dual-ubi-request.v1','board_target':'am2-s19jpro-zynq','source':'braiins-dual-ubi-mtd7-mtd8','mac':'02:00:00:00:00:01','hwid':'fixture123','active_mtd':'7','kernel_sha256':sha(p/'kernel'),'rootfs_sha256':sha(p/'rootfs'),'config_sha256':sha(p/'dcentrald.toml'),'proc_mtd_sha256':sha(root/'proc/mtd'),'fw_env_sha256':sha(root/'etc/fw_env.config'),'capsule_sha256':'f'*64}
request.update(fpga_sha256=sha(p/'am2-fabric.itb'),writer_sha256=sha(p/'am2-nand-window'),bootenv_sha256=sha(p/'env.boot'),env_before_sha256=sha(Path(sys.argv[4])))
request.update(ssh_host_rsa_sha256=sha(p/'ssh-host-rsa'),ssh_host_ed25519_sha256=sha(p/'ssh-host-ed25519'),ssh_authorized_keys_sha256=sha(p/'ssh-authorized_keys'))
(p/'request').write_text(''.join(f'{k}={v}\n' for k,v in sorted(request.items())))
PY
REQUEST_SHA=$(sha256sum "$TX/request" | awk '{print $1}')
for mode in preflight install; do
    if [[ "$mode" == install && -n "${DCENT_AM2_POWERCUT_CONTROL:-}" ]]; then
        # Test-only process observation wraps the unchanged production shell.
        # Its selected boundary never resumes: the owned host saves only raw
        # simulator NAND/OOB and SIGKILLs QEMU without a guest flush/cleanup.
        python3 "$SCRIPT_DIR/virtme/am2-ubi/guest_powercut.py" trace \
            --control "$DCENT_AM2_POWERCUT_CONTROL" --token "$DCENT_AM2_POWERCUT_TOKEN" \
            --cut "$DCENT_AM2_POWERCUT_INDEX" --root "$ROOT" --work "$WORK" \
            --request-sha "$REQUEST_SHA" | tee "$WORK/$mode.log"
    else
        chroot "$ROOT" /bin/sh /tmp/transaction/stage1.sh "$mode" /tmp/transaction "$REQUEST_SHA" | tee "$WORK/$mode.log"
    fi
done
grep -qx state=committed "$WORK/install.log"
chroot "$ROOT" fw_printenv -c /etc/fw_env.config firmware | grep -qx firmware=2
chroot "$ROOT" fw_printenv -c /etc/fw_env.config dcent_native_slot | grep -qx dcent_native_slot=2
head -c "$(wc -c < "$TX/am2-fabric.itb")" /dev/mtd3 > "$WORK/fpga.readback"
cmp "$TX/am2-fabric.itb" "$WORK/fpga.readback"
# The finite helper itself also refuses the active FPGA before mutation.
if chroot "$ROOT" /tmp/transaction/am2-nand-window write dual10 fpga1 /tmp/transaction/am2-fabric.itb; then exit 1; fi
ubiattach -m 8 -d 1 -O 2048 --max-beb-per1024=20 >/dev/null
for row in 'kernel 0' 'rootfs 1'; do
    read -r name id <<< "$row"
    head -c "$(wc -c < "$TX/$name")" "/dev/ubi1_$id" > "$WORK/readback"
    cmp "$TX/$name" "$WORK/readback"
done
mkdir "$WORK/verify-data"
mount -t ubifs -o ro ubi1:rootfs_data "$WORK/verify-data"
cmp "$TX/dcentrald.toml" "$WORK/verify-data/dcentrald.toml"
cmp "$TX/env.before" "$WORK/verify-data/vendor-first-install/env.before"
cmp "$TX/ssh-host-ed25519" "$WORK/verify-data/keys/dropbear/dropbear_ed25519_host_key"
cmp "$TX/ssh-authorized_keys" "$WORK/verify-data/dcent/authorized_keys"
test -f "$WORK/verify-data/dcent/.ssh-enabled"
tar -xOf "$WORK/verify-data/vendor-first-install/overlay.tar" ./pools.conf | cmp - "$ROOT/overlay/pools.conf"
umount "$WORK/verify-data"
# Simulate U-Boot's first-attempt bookkeeping and the new slot's /data mount.
# This is a storage lifecycle check, not a claim that the miner image booted.
chroot "$ROOT" fw_setenv -c /etc/fw_env.config upgrade_stage 1
printf 'console=ttyPS0 ubi.mtd=8 root=ubi0:rootfs\n' > "$WORK/identity/cmdline"
mkdir "$ROOT/data"
mount -t ubifs -o rw ubi1:rootfs_data "$ROOT/data"
chroot "$ROOT" /bin/sh /data/vendor-first-install/stage1.sh rollback /data/vendor-first-install "$REQUEST_SHA" | tee "$WORK/rollback.log"
grep -qx state=rolled_back "$WORK/rollback.log"
umount "$ROOT/data"
ubidetach -d 1
chroot "$ROOT" fw_printenv -c /etc/fw_env.config > "$WORK/env.after"
cmp "$WORK/env.before" "$WORK/env.after"
nanddump -q --omitoob --bb=padbad /dev/mtd7 | sha256sum > "$WORK/active.after"
nanddump -q --omitoob --bb=padbad /dev/mtd9 | sha256sum > "$WORK/factory.after"
nanddump -q --omitoob --bb=padbad /dev/mtd2 | sha256sum > "$WORK/fpga-active.after"
cmp "$WORK/active.before" "$WORK/active.after"
cmp "$WORK/factory.before" "$WORK/factory.after"
cmp "$WORK/fpga-active.before" "$WORK/fpga-active.after"
echo AM2_FIRST_INSTALL_NANDSIM_OK
echo "AM2_FIRST_INSTALL_NANDSIM_LAYOUT=$LAYOUT"
