#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Disposable real-MTD tests for the first-party finite stock NAND writer.
set -euo pipefail
WORK=${1:-}; HELPER=${2:-}; ARM_HELPER=${3:-}
[[ "$WORK" == /tmp/dcent-am2-stock-window-* && ! -e "$WORK" ]] || exit 64
[[ -f "$HELPER" && ! -L "$HELPER" ]] || exit 64
[[ -f "$ARM_HELPER" && ! -L "$ARM_HELPER" ]] || exit 64
[[ "${DCENT_DISPOSABLE_VIRTME:-}" == am2-stock-window-v1 && $(id -u) == 0 ]] || exit 64
grep -Eq 'QEMU|KVM|Standard PC' /sys/class/dmi/id/product_name || exit 64
[[ ! -e /proc/mtd ]] || [[ $(awk 'END {print NR}' /proc/mtd) == 1 ]] || exit 64
mkdir -m 700 "$WORK"
mount --make-rprivate /
modprobe nandsim id_bytes=0x20,0xaa,0x00,0x15 overridesize=11 parts=320,256,64,16,112,128,448
awk 'NR>1 && $0 !~ /NAND simulator/ {exit 1} END {if(NR!=9) exit 1}' /proc/mtd
for node in /sys/class/mtd/mtd[0-9]*; do
    [[ -f "$node/dev" ]] || continue
    name=${node##*/}; IFS=: read -r major minor < "$node/dev"
    [[ -c /dev/$name ]] || mknod "/dev/$name" c "$major" "$minor"
done
ROOT="$WORK/root"
mkdir -p "$ROOT"/{bin,usr,lib,lib64,dev,proc,sys,tmp} "$WORK/identity"
mount --bind "$ROOT" "$ROOT"
for path in bin usr lib lib64 dev proc sys; do
    [[ -d /$path ]] && mount --rbind "/$path" "$ROOT/$path"
done
cleanup() {
    rc=$?; trap - EXIT
    umount -R "$ROOT" 2>/dev/null || true
    modprobe -r nandsim 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
python3 - "$WORK/identity" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
parts=[('BOOT.bin-dts-marker-kernel',40),('ramfs',32),('configs',8),('sig',2),('reserve1',14),('upgrade-ramfs',16),('upgrade-file',56),('reserve2',88)]
(p/'proc-mtd').write_text('dev:    size   erasesize  name\n'+''.join(f'mtd{i}: {mib*1048576:08x} 00020000 "{name}"\n' for i,(name,mib) in enumerate(parts)))
for i,(name,_) in enumerate(parts): (p/f'name{i}').write_text(name+'\n')
(p/'cmdline').write_text('console=ttyPS0 root=/dev/ram0 rootfstype=squashfs\n')
PY
mount --bind "$WORK/identity/proc-mtd" "$ROOT/proc/mtd"
mount --bind "$WORK/identity/cmdline" "$ROOT/proc/cmdline"
for i in {0..7}; do
    mount --bind "$WORK/identity/name$i" "$ROOT/sys/class/mtd/mtd$i/name"
done
cp "$HELPER" "$ROOT/tmp/am2-nand-window"
python3 - "$ROOT/tmp" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
(p/'stock-kernel').write_bytes(b'original stock kernel\n'*65536)
(p/'transition').write_bytes(b'candidate transition kernel\n'*32768)
with (p/'oversized').open('wb') as f: f.truncate(8*1048576+1)
PY
invoke() { chroot "$ROOT" /tmp/am2-nand-window "$@"; }
invoke check stock8 transition-kernel
invoke write stock8 transition-kernel /tmp/stock-kernel
invoke read stock8 transition-kernel /tmp/original-window
# The first 32 MiB include the original boot chain and both future environment
# regions. No raw environment/miner_cfg window is exposed by this helper.
nanddump -q --omitoob --bb=padbad -l 33554432 /dev/mtd0 | sha256sum > "$WORK/prefix.before"
invoke write stock8 transition-kernel /tmp/transition
invoke read stock8 transition-kernel /tmp/new-window
python3 - "$ROOT/tmp" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); payload=(p/'transition').read_bytes(); observed=(p/'new-window').read_bytes()
assert len(observed)==8*1048576 and observed[:len(payload)]==payload
assert observed[len(payload):]==b'\xff'*(len(observed)-len(payload))
PY
if invoke write stock8 transition-kernel /tmp/oversized; then exit 1; fi
if invoke write stock8 uboot_env /tmp/transition; then exit 1; fi
invoke read stock8 transition-kernel /tmp/after-refusal
cmp "$ROOT/tmp/new-window" "$ROOT/tmp/after-refusal"
invoke write stock8 transition-kernel /tmp/original-window
invoke read stock8 transition-kernel /tmp/restored-window
cmp "$ROOT/tmp/original-window" "$ROOT/tmp/restored-window"
nanddump -q --omitoob --bb=padbad -l 33554432 /dev/mtd0 | sha256sum > "$WORK/prefix.after"
cmp "$WORK/prefix.before" "$WORK/prefix.after"
# Repeat the real write/readback/restore through the self-contained ARMv7
# executable. qemu-user forwards its MTD ioctl ABI to this same guest kernel.
cp "$ARM_HELPER" "$ROOT/tmp/am2-nand-window-armv7"
invoke_arm() { chroot "$ROOT" /usr/bin/qemu-arm-static /tmp/am2-nand-window-armv7 "$@"; }
invoke_arm check stock8 transition-kernel
invoke_arm write stock8 transition-kernel /tmp/transition
invoke_arm read stock8 transition-kernel /tmp/arm-new-window
cmp "$ROOT/tmp/new-window" "$ROOT/tmp/arm-new-window"
invoke_arm write stock8 transition-kernel /tmp/original-window
invoke_arm read stock8 transition-kernel /tmp/arm-restored-window
cmp "$ROOT/tmp/original-window" "$ROOT/tmp/arm-restored-window"
# A known bad block in the physical window must refuse before erase/write.
# This ioctl marks only the disposable simulator, never an attached host MTD.
python3 - <<'PY'
import fcntl,struct
with open('/dev/mtd0','r+b',buffering=0) as f:
    fcntl.ioctl(f.fileno(),0x40084d0c,struct.pack('q',0x27e0000))
PY
if invoke write stock8 transition-kernel /tmp/transition; then exit 1; fi
if invoke_arm write stock8 transition-kernel /tmp/transition; then exit 1; fi
nanddump -q --omitoob --bb=dumpbad -s 33554432 -l 8388608 /dev/mtd0 > "$WORK/after-bad-refusal"
cmp "$ROOT/tmp/original-window" "$WORK/after-bad-refusal"
echo AM2_STOCK_WINDOW_NANDSIM_OK
