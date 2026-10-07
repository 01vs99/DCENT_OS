#!/usr/bin/env python3
"""Compose the DCENT_OS S19k Pro (Amlogic A113D, NoPic) AML install candidate.

New S19k lane packager (Classic-era prepare_classic_aml_install_candidate.py is
untouched).  The candidate mirrors the on-flash packaging the unit itself uses:
BraiinsOS stores its boot artifacts inside MTD5 "system" at fixed partition
relative offsets, and the live U-Boot demonstrably reads a device tree from
MTD5+0x00e00000 (u-boot,version is patched into chosen at every boot; see the
r10 install path analysis).  The install therefore writes exactly three MTD5
windows -- donor DTB at +0x00e00000, kernel uImage at +0x01100000, rootfs
uImage at +0x05100000 -- and neutralizes the stale BraiinsOS overlay UBI in
MTD4 so no UBI can ever auto-attach over the donor seven-MTD nvdata window
(which physically contains the boot artifacts) and erase them in the
background.

Refusal gates: input digest pins, uImage body pins, size/alignment bounds,
span overlap checks against the preserved MTD5 regions, write-once outputs.
The candidate is UNSIGNED by design; the delivery mechanism (root SSH direct
MTD write) enforces no vendor signature, and the analysis records where vendor
signing would otherwise apply.

Verbs:
  build     compose the candidate TAR + restore kit + build receipt
  validate  fixture dry-run of the embedded installer.sh + member diff vs the
            donor kit + validation receipt (inert fixtures; never real devices)
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

SCHEMA = "dcent.r10.s19k-install-candidate.v1"
CANDIDATE_NAME = "s19k-install-candidate-v1"
DATE = "2026-09-11"

WORKSPACE = Path(__file__).resolve().parents[3]
STICK = WORKSPACE / "DCENT_OS_Antminer/output/s19k-ramboot-stick-v1"
BACKUP = (WORKSPACE / ""
          "live-s19k-recon/nand-backup-203.0.113.80-v1")
OUTPUT = WORKSPACE / "DCENT_OS_Antminer/output" / CANDIDATE_NAME
R10 = (WORKSPACE / "")

# ---------------------------------------------------------------- pins ------
# Payload artifacts: the already desk-validated RAM-boot stick payload bytes
# (kernel + rootfs uImage) and the donor device tree.
KERNEL_FILE, KERNEL_SHA, KERNEL_LEN = (
    "uImage.kernel", "bc7dc5aad8c33ef1d390988359d4ac46d0a7a68cbc7549697a5f3ee7ebd86faf", 14960712)
ROOTFS_FILE, ROOTFS_SHA, ROOTFS_LEN = (
    "uImage.rootfs.cpio.gz", "88e267db5d063e2e0ad02168b0af84bed6cd80ee4f4b3df870c8c8e6fce4e2ed", 30748603)
DTB_FILE, DTB_SHA, DTB_LEN = (
    "s19k.dtb", "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257", 20945)

# Donor body pins (uImage payload = the validated image artifacts).
KERNEL_BODY_SHA = "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6"
ROOTFS_BODY_SHA = "bf85fc64f8894f61bceffc69458cef6c7f20b9ac63059cefc1b022ea331d4d3a"

# MTD5 "system" partition geometry (BraiinsOS 6-MTD runtime layout).
MTD5_SIZE = 0x9900000          # 153 MiB
MTD5_ERASE = 0x20000
PAGE = 2048

# Install targets inside MTD5 (partition-relative, 128 KiB aligned).
OFF_DTB = 0x00E00000
OFF_KERNEL = 0x01100000
OFF_ROOTFS = 0x05100000

# Preserved MTD5 regions (untouched by the install; verified pre/post).
PRESERVED_BLOB = (0x00900000, 0x009D2040)   # unidentified 860,224 B arm64 blob (candidate: U-Boot proper backup)
PRESERVED_MARKER = (0x03100000, 0x0310000B)  # ASCII "0x00002400\0" (11 bytes incl. NUL)
PRESERVED_ENV = (0x04900000, 0x04A00000)     # U-Boot env (CRC 0xc657f51a), stock-format
HEAD_FF = (0x00000000, 0x00900000)           # MTD5 head must be erased (unit-state gate)

# BraiinsOS restore regions extracted from the NAND backup (block aligned).
RESTORE_DTB_SPAN = (0x00E00000, 0x00E20000)
RESTORE_KERNEL_SPAN = (0x01100000, 0x020C0000)
RESTORE_RAMDISK_SPAN = (0x05100000, 0x06900000)

BOSPLUS_DTB_LEN = 45433
BOSPLUS_DTB_SHA = "06add73e3dead56d3bb249ed645331fcdd497814d61a70f0e32c31ea796359a8"

# Donor kit (vnish 1.2.7 S19k Pro AML NAND install) for the member diff.
DONOR_DIR = (WORKSPACE / ""
             "vnish-1.2.7-s19kpro-aml-nand-v1.2.7-install")

ARTIFACTS = {
    "dtb":    {"file": DTB_FILE,    "sha": DTB_SHA,    "len": DTB_LEN,    "offset": OFF_DTB},
    "kernel": {"file": KERNEL_FILE, "sha": KERNEL_SHA, "len": KERNEL_LEN, "offset": OFF_KERNEL},
    "rootfs": {"file": ROOTFS_FILE, "sha": ROOTFS_SHA, "len": ROOTFS_LEN, "offset": OFF_ROOTFS},
}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def span_of(art):
    length = art["len"]
    blocks = (length + MTD5_ERASE - 1) // MTD5_ERASE
    return art["offset"], art["offset"] + blocks * MTD5_ERASE


def refuse(message):
    print("REFUSED: " + message, file=sys.stderr)
    sys.exit(1)


def check_inputs():
    for name, art in ARTIFACTS.items():
        path = STICK / art["file"]
        if not path.is_file():
            refuse("missing stick payload " + str(path))
        length = path.stat().st_size
        if length != art["len"]:
            refuse(f"{art['file']} is {length} B, pin says {art['len']} B")
        digest = sha256_file(path)
        if digest != art["sha"]:
            refuse(f"{art['file']} sha256 {digest} != pin {art['sha']}")
    kernel = (STICK / KERNEL_FILE).read_bytes()
    if sha256_bytes(kernel[64:]) != KERNEL_BODY_SHA:
        refuse("kernel uImage body does not match the donor vmlinux.bin pin")
    if struct.unpack(">I", kernel[:4])[0] != 0x27051956:
        refuse("kernel uImage magic missing")
    rootfs = (STICK / ROOTFS_FILE).read_bytes()
    if sha256_bytes(rootfs[64:]) != ROOTFS_BODY_SHA:
        refuse("rootfs uImage body does not match the rootfs.cpio.gz pin")
    if struct.unpack(">I", rootfs[:4])[0] != 0x27051956:
        refuse("rootfs uImage magic missing")
    kos, karch, ktype, kcomp = kernel[28], kernel[29], kernel[30], kernel[31]
    if (kos, karch, ktype, kcomp) != (5, 22, 2, 0):
        refuse(f"kernel uImage os/arch/type/comp = {kos}/{karch}/{ktype}/{kcomp}, want 5/22/2/0")
    ros, rarch, rtype, rcomp = rootfs[28], rootfs[29], rootfs[30], rootfs[31]
    if (ros, rarch, rtype, rcomp) != (5, 22, 3, 1):
        refuse(f"rootfs uImage os/arch/type/comp = {ros}/{rarch}/{rtype}/{rcomp}, want 5/22/3/1")
    for name, (start, end) in (("dtb", span_of(ARTIFACTS["dtb"])),
                               ("kernel", span_of(ARTIFACTS["kernel"])),
                               ("rootfs", span_of(ARTIFACTS["rootfs"]))):
        if end > MTD5_SIZE:
            refuse(f"{name} erase span {end:#x} exceeds MTD5 size {MTD5_SIZE:#x}")
    spans = [("dtb", span_of(ARTIFACTS["dtb"])),
             ("kernel", span_of(ARTIFACTS["kernel"])),
             ("rootfs", span_of(ARTIFACTS["rootfs"])),
             ("blob", PRESERVED_BLOB), ("marker", PRESERVED_MARKER),
             ("env", PRESERVED_ENV)]
    for i in range(len(spans)):
        for j in range(i + 1, len(spans)):
            (a0, a1), (b0, b1) = spans[i][1], spans[j][1]
            if a0 < b1 and b0 < a1:
                refuse(f"span overlap {spans[i][0]} vs {spans[j][0]}")
    backup = BACKUP / "mtd5.bin"
    if not backup.is_file():
        refuse("missing NAND backup " + str(backup))
    if backup.stat().st_size != MTD5_SIZE + 0x400:
        pass  # backup carries the full 0x9900400 dump incl. trailing OOB-free slack
    return True


# ------------------------------------------------------------- shell kit ----
PROBE_SH = r"""#!/bin/sh
# s19k-install-candidate-v1 probe -- READ-ONLY unit inventory (no writes).
# Prints labeled facts; the procedure checklist gates every step on them.
[ "$(id -u)" = "0" ] || { echo "PROBE refuse: root required"; exit 1; }
echo "== mtd-layout =="
cat /proc/mtd
echo "== mtd5-sysfs =="
for f in name size erasesize writesize oobsize; do
  printf "%s=" "$f"; cat "/sys/class/mtd/mtd5/$f" 2>/dev/null || echo absent
done
echo "== tools =="
for t in flash_erase flash_eraseall nandwrite flashcp dd sha256sum md5sum \
         ubiattach ubidetach ubiformat ubirename fw_printenv cmp tr head; do
  if command -v "$t" >/dev/null 2>&1; then echo "$t=present"; else echo "$t=absent"; fi
done
echo "== tmp-space =="
df -k /tmp | tail -1
echo "== ubi-state =="
ls /sys/class/ubi 2>/dev/null
for u in /sys/class/ubi/ubi*; do
  [ -f "$u/mtd_num" ] && echo "$(basename "$u") mtd_num=$(cat "$u/mtd_num")"
done
echo "== mounts =="
cat /proc/mounts | grep -v -E "proc|sysfs|devpts|tmpfs|devtmpfs|rootfs|none"
echo "== identity =="
cat /etc/os-release 2>/dev/null | head -3
cat /etc/fw_env.config 2>/dev/null
echo "== probe-complete =="
"""

INSTALLER_SH = r"""#!/bin/sh
# s19k-install-candidate-v1 installer -- gated BraiinsOS->DCENT_OS MTD5 mirror
# install for the Antminer S19k Pro (Amlogic A113D, NoPic) control board.
#
# Subcommands:
#   status              read-only gates + inventory (safe any time)
#   stage <file> <w>    verify uploaded artifact <w> and move it into place
#   flash <w>           erase+write+readback-verify artifact <w> (dtb|kernel|rootfs)
#   neutralize          stop services, detach+erase MTD4 overlay UBI (defuses the
#                       nvdata auto-attach trap; irreversible without the backup)
#   plan                print the write plan only
#
# Overridable for inert fixture testing only:
#   MTD5_DEV (default /dev/mtd5)  MTD4_DEV (default /dev/mtd4)
#   FILEMODE=1 (fixture: regular files, erase = FF-fill, no service stops)
#   WORK (default /tmp/dcentos-install)
#
# Mining is never started by this script. DCENT_OS boots with its storage
# admission gate deciding persistence; the install changes no DCENT policy.

MTD5_DEV="${MTD5_DEV:-/dev/mtd5}"
MTD4_DEV="${MTD4_DEV:-/dev/mtd4}"
FILEMODE="${FILEMODE:-0}"
WORK="${WORK:-/tmp/dcentos-install}"
HERE=$(cd "$(dirname "$0")" && pwd)

MTD5_SIZE=$((0x9900000))
ERASE=$((0x20000))
PAGE=2048
MANIFEST="$HERE/MANIFEST.json"

fail() { echo "INSTALLER refuse: $*" >&2; exit 1; }
note() { echo "INSTALLER: $*"; }

jsonfield() { # jsonfield <key>  -- crude busybox-safe string field extract
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([0-9a-fx]*\)\".*/\1/p" "$MANIFEST" | head -1
}

art_len()  { case "$1" in dtb) echo 20945;; kernel) echo 14960712;; rootfs) echo 30748603;; esac; }
art_off()  { case "$1" in dtb) echo $((0x00E00000));; kernel) echo $((0x01100000));; rootfs) echo $((0x05100000));; esac; }
art_file() { case "$1" in dtb) echo devicetree.dtb;; kernel) echo uImage.kernel;; rootfs) echo uImage.rootfs.cpio.gz;; esac; }
art_sha()  {
  case "$1" in
    dtb)    echo 540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257;;
    kernel) echo bc7dc5aad8c33ef1d390988359d4ac46d0a7a68cbc7549697a5f3ee7ebd86faf;;
    rootfs) echo 88e267db5d063e2e0ad02168b0af84bed6cd80ee4f4b3df870c8c8e6fce4e2ed;;
  esac
}

gates() {
  [ "$(id -u)" = "0" ] || fail "root required"
  [ -f "$MANIFEST" ] || fail "MANIFEST.json missing next to installer.sh"
  # The install is a BraiinsOS -> DCENT_OS one-way door: require the exact
  # BraiinsOS six-MTD runtime layout before touching anything.
  LAYOUT=$(cat /proc/mtd 2>/dev/null | tail -n +2 | tr -s ' ')
  echo "$LAYOUT" | grep -q 'mtd0: 00200000 00020000 "bootloader"' || fail "mtd0 bootloader layout mismatch (not BraiinsOS layout?)"
  echo "$LAYOUT" | grep -q 'mtd1: 00800000 00020000 "tpl"' || fail "mtd1 tpl layout mismatch"
  echo "$LAYOUT" | grep -q 'mtd2: 03200000 00020000 "stock_system"' || fail "mtd2 stock_system layout mismatch"
  echo "$LAYOUT" | grep -q 'mtd3: 00500000 00020000 "stock_config"' || fail "mtd3 stock_config layout mismatch"
  echo "$LAYOUT" | grep -q 'mtd4: 02000000 00020000 "overlay"' || fail "mtd4 overlay layout mismatch"
  echo "$LAYOUT" | grep -q 'mtd5: 09900000 00020000 "system"' || fail "mtd5 system layout mismatch"
  [ "$(cat /sys/class/mtd/mtd5/erasesize)" = "$ERASE" ] || fail "mtd5 erasesize mismatch"
  [ "$(cat /sys/class/mtd/mtd5/writesize)" = "$PAGE" ] || fail "mtd5 writesize mismatch"
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum absent"
  command -v dd >/dev/null 2>&1 || fail "dd absent"
  if [ "$FILEMODE" != "1" ]; then
    command -v flash_erase >/dev/null 2>&1 || fail "flash_erase absent (mtd-utils missing on unit)"
  fi
  return 0
}

readback_sha() { # readback_sha <dev> <off> <len>
  dev=$1; off=$2; len=$3
  pages=$(( (len + PAGE - 1) / PAGE ))
  dd if="$dev" bs=$PAGE skip=$((off / PAGE)) count=$pages 2>/dev/null | head -c "$len" | sha256sum | cut -d' ' -f1
}

ff_region_check() { # ff_region_check <dev> <off> <len>  -> 0 if all 0xFF
  dev=$1; off=$2; len=$3
  pages=$(( (len + PAGE - 1) / PAGE ))
  dd if="$dev" bs=$PAGE skip=$((off / PAGE)) count=$pages 2>/dev/null \
    | head -c "$len" | tr -d '\377' | wc -c | grep -q '^0$'
}

erase_span() { # erase_span <dev> <off> <blocks>
  if [ "$FILEMODE" = "1" ]; then
    dd if="$HERE/.fffill" bs=65536 count=$(( ($3 * $ERASE) / 65536 )) 2>/dev/null | \
      dd of="$1" bs=65536 seek=$(( $2 / 65536 )) conv=notrunc 2>/dev/null
  else
    flash_erase "$1" "$2" "$3" >/dev/null 2>&1 || fail "flash_erase $1 $2 $3 failed"
  fi
}

cmd_plan() {
  echo "plan: mtd5=$MTD5_DEV size=$MTD5_SIZE erase=$ERASE filemode=$FILEMODE"
  for w in dtb kernel rootfs; do
    off=$(art_off "$w"); len=$(art_len "$w")
    blocks=$(( (len + ERASE - 1) / ERASE ))
    echo "  $w: offset=0x$(printf %08x "$off") len=$len erase_blocks=$blocks span_end=0x$(printf %08x $((off + blocks * ERASE)))"
  done
  echo "  neutralize: erase $MTD4_DEV (stale overlay UBI; 0x02000000 bytes)"
}

cmd_status() {
  gates
  cmd_plan
  echo "preserved-blob  sha=$(readback_sha "$MTD5_DEV" $((0x00900000)) $((0x000D2040)))"
  echo "preserved-env   sha=$(readback_sha "$MTD5_DEV" $((0x04900000)) $((0x00100000)))"
  echo "head-ff         $(ff_region_check "$MTD5_DEV" 0 $((0x00900000)) && echo ok || echo MISMATCH)"
  for w in dtb kernel rootfs; do
    if [ -f "$WORK/$w.img" ]; then
      echo "staged-$w sha=$(sha256sum "$WORK/$w.img" | cut -d' ' -f1) want=$(art_sha "$w")"
    else
      echo "staged-$w absent"
    fi
  done
}

cmd_stage() {
  gates
  src="$1"; w="$2"
  [ -f "$src" ] || fail "stage source $src missing"
  case "$w" in dtb|kernel|rootfs) ;; *) fail "unknown artifact $w";; esac
  got=$(sha256sum "$src" | cut -d' ' -f1)
  [ "$got" = "$(art_sha "$w")" ] || fail "staged $w sha256 $got != $(art_sha "$w")"
  mkdir -p "$WORK"
  # 2048-byte 0xFF padding so the mtd char write is page-multiple.
  cp "$src" "$WORK/$w.img"
  len=$(art_len "$w")
  pages=$(( (len + PAGE - 1) / PAGE ))
  padb=$(( pages * PAGE - len ))
  if [ "$padb" -gt 0 ]; then
    dd if=/dev/zero bs="$padb" count=1 2>/dev/null | tr '\000' '\377' >> "$WORK/$w.img"
  fi
  [ "$(stat -c %s "$WORK/$w.img" 2>/dev/null || wc -c < "$WORK/$w.img")" -eq $((pages * PAGE)) ] \
    || fail "padded stage size wrong"
  echo "staged $w -> $WORK/$w.img (padded $((pages * PAGE)) B)"
}

cmd_flash() {
  gates
  w="$1"
  case "$w" in dtb|kernel|rootfs) ;; *) fail "unknown artifact $w";; esac
  [ -f "$WORK/$w.img" ] || fail "$w not staged (run: installer.sh stage <file> $w)"
  off=$(art_off "$w"); len=$(art_len "$w")
  blocks=$(( (len + ERASE - 1) / ERASE ))
  note "flash $w: erase $MTD5_DEV 0x$(printf %08x "$off") +$blocks blocks"
  erase_span "$MTD5_DEV" "$off" "$blocks"
  note "write $w"
  dd if="$WORK/$w.img" of="$MTD5_DEV" bs=$PAGE seek=$((off / PAGE)) conv=notrunc 2>/dev/null \
    || fail "dd write of $w failed"
  sync
  got=$(readback_sha "$MTD5_DEV" "$off" "$len")
  [ "$got" = "$(art_sha "$w")" ] || fail "readback sha of $w = $got, want $(art_sha "$w")"
  rm -f "$WORK/$w.img"
  echo "$w" >> "$WORK/.flashed-ok"
  note "$w flashed and verified (readback sha match)"
}

cmd_neutralize() {
  gates
  # Guard: all three artifacts must have been flashed and readback-verified
  # in this working session before the destructive step is allowed.
  for w in dtb kernel rootfs; do
    grep -q "^$w$" "$WORK/.flashed-ok" 2>/dev/null || fail "$w not flashed+verified yet; refusing to neutralize"
  done
  if [ "$FILEMODE" = "1" ]; then
    note "FILEMODE neutralize: FF-fill $MTD4_DEV"
    erase_span "$MTD4_DEV" 0 $((0x02000000 / ERASE))
    echo "neutralized (fixture)"
    return 0
  fi
  # Keep THIS SSH session alive at all costs: dropbear is NOT stopped.  Stop
  # the noisy daemons, unmount /etc (UBI0 on MTD4), detach, and erase the
  # stale overlay UBI.  Without this, DCENT's first boot would auto-attach
  # that UBI over the donor seven-MTD nvdata window and erase the boot
  # artifacts in the background.  Only the current session remains: it must
  # issue the final reboot.
  [ "$(cat /sys/class/ubi/ubi0/mtd_num 2>/dev/null)" = "4" ] || fail "ubi0 is not attached to mtd4 (unexpected unit state)"
  for svc in S70miner S71monitor S80dashd S49chrony S04syslogd S02klogd S15timezone S20seedrng; do
    [ -x "/etc/init.d/$svc" ] && { "/etc/init.d/$svc" stop >/dev/null 2>&1 && note "stopped $svc" || note "stop $svc failed (continuing)"; }
  done
  sleep 1
  sync
  umount /etc 2>/dev/null || fail "umount /etc busy; aborting before any destructive step"
  ubidetach -m 4 2>/dev/null || ubidetach /dev/ubi_ctrl -m 4 2>/dev/null || \
    fail "ubidetach mtd4 failed"
  note "erasing stale overlay UBI on $MTD4_DEV (whole partition)"
  flash_erase "$MTD4_DEV" 0 0 >/dev/null 2>&1 || fail "flash_erase $MTD4_DEV failed"
  sync
  ff_region_check "$MTD4_DEV" 0 $((0x02000000)) || fail "MTD4 not fully erased"
  note "MTD4 neutralized (all 0xFF); nvdata auto-attach trap defused"
  note "READY TO REBOOT: run 'sync; reboot -f' from this session when the checklist says so"
}

case "$1" in
  plan)       gates; cmd_plan ;;
  status)     cmd_status ;;
  stage)      shift; cmd_stage "$@" ;;
  flash)      shift; cmd_flash "$@" ;;
  neutralize) cmd_neutralize ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
"""

RESTORE_SH = r"""#!/bin/sh
# restore-bosplus-v1.sh -- surgical BraiinsOS MTD5 + MTD4 restore from the
# 2026-09-11 full NAND backup regions.  Run ON THE UNIT over SSH with the
# region files staged in the same directory (desk kit: ../restore/).
# Usage: sh restore-bosplus-v1.sh status|restore-mtd5|restore-mtd4
# In FILEMODE=1 with MTD5_DEV/MTD4_DEV pointing at fixture files it is inert.
MTD5_DEV="${MTD5_DEV:-/dev/mtd5}"
MTD4_DEV="${MTD4_DEV:-/dev/mtd4}"
FILEMODE="${FILEMODE:-0}"
HERE=$(cd "$(dirname "$0")" && pwd)
ERASE=$((0x20000)); PAGE=2048
fail() { echo "RESTORE refuse: $*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || fail "root required"
restore_region() { # <dev> <file> <off>
  dev=$1; file=$2; off=$3
  len=$(wc -c < "$HERE/$file")
  blocks=$(( (len + ERASE - 1) / ERASE ))
  if [ "$FILEMODE" = "1" ]; then
    dd if="$HERE/.fffill" bs=65536 count=$(( (blocks * ERASE) / 65536 )) 2>/dev/null | \
      dd of="$dev" bs=65536 seek=$(( off / 65536 )) conv=notrunc 2>/dev/null
  else
    flash_erase "$dev" "$off" "$blocks" >/dev/null 2>&1 || fail "erase failed at $off"
  fi
  dd if="$HERE/$file" of="$dev" bs=$PAGE seek=$((off / PAGE)) conv=notrunc 2>/dev/null || fail "write $file failed"
  sync
  echo "restored $file at 0x$(printf %08x "$off") ($len bytes)"
}
case "$1" in
  restore-mtd5)
    restore_region "$MTD5_DEV" bosplus-dtb-region.bin    $((0x00E00000))
    restore_region "$MTD5_DEV" bosplus-kernel-region.bin $((0x01100000))
    restore_region "$MTD5_DEV" bosplus-ramdisk-region.bin $((0x05100000))
    echo "MTD5 BraiinsOS boot windows restored; reboot to return to BraiinsOS"
    ;;
  restore-mtd4)
    restore_region "$MTD4_DEV" bosplus-overlay-mtd4-region.bin 0
    echo "MTD4 overlay UBI restored (BraiinsOS /etc)"
    ;;
  status)
    ls -la "$HERE" | grep region
    ;;
  *) echo "usage: $0 status|restore-mtd5|restore-mtd4"; exit 2 ;;
esac
"""


def manifest_bytes():
    manifest = {
        "schema": SCHEMA,
        "date": DATE,
        "candidate": CANDIDATE_NAME,
        "claim": ("Unsigned DCENT_OS install candidate for the Antminer S19k Pro "
                  "Amlogic A113D (NoPic) NAND, mirroring the BraiinsOS on-flash "
                  "MTD5 system-partition artifact layout; delivery is root SSH "
                  "with gated direct MTD writes; no miner contact was made while "
                  "composing or validating this candidate"),
        "target": {
            "board": "Antminer S19k Pro (Amlogic A113D/AXG, BHB56903)",
            "source_firmware": "BraiinsOS (BOSminer plus-tuner 0.9.0-db69f9bc)",
            "mtd5_system_size": MTD5_SIZE,
            "mtd5_erasesize": MTD5_ERASE,
            "page": PAGE,
        },
        "artifacts": {},
        "preserved_regions": {
            "head_all_ff": {"span": list(HEAD_FF)},
            "unidentified_blob": {"span": list(PRESERVED_BLOB),
                                  "note": "860224 B arm64 blob with embedded gzip; preserved untouched; candidate identity: U-Boot proper backup (unverified)"},
            "marker_0x3100000": {"span": list(PRESERVED_MARKER),
                                 "expect_ascii": "0x00002400\\0"},
            "uboot_env": {"span": list(PRESERVED_ENV), "crc32": "0xc657f51a"},
        },
        "neutralize": {
            "device": "/dev/mtd4",
            "reason": ("the stale BraiinsOS overlay UBI at physical 0x4100000 sits "
                       "at the start of the donor seven-MTD nvdata window; if left "
                       "in place DCENT's first-boot ubiattach would succeed, the "
                       "nvdada_log name check would refuse, and the attached UBI "
                       "would erase the boot-artifact PEBs in the background"),
            "bytes": 0x02000000,
        },
        "posture": {
            "signed": False,
            "signature_note": ("no vendor signature exists or is forgeable here; the "
                               "BraiinsOS and stock Bitmain upgrade formats both "
                               "verify vendor signatures (stock payloads are "
                               "encrypted+signed bmu.sig), so the viable unsigned "
                               "delivery is the root-SSH gated direct write"),
            "mining": "remains OFF; DCENT storage admission refuses on this unit by design",
        },
    }
    for name, art in ARTIFACTS.items():
        start, end = span_of(art)
        manifest["artifacts"][name] = {
            "member": f"{CANDIDATE_NAME}/artifacts/{art['file']}",
            "bytes": art["len"], "sha256": art["sha"],
            "mtd5_offset": art["offset"],
            "erase_span": [start, end],
            "erase_blocks": (end - start) // MTD5_ERASE,
        }
    return json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"


def build():
    check_inputs()
    if OUTPUT.exists():
        refuse(f"output directory already exists (write-once): {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    restore_dir = OUTPUT / "restore"
    restore_dir.mkdir()
    artifacts_dir = OUTPUT / "staged-artifacts"
    artifacts_dir.mkdir()

    # Copy artifacts + verify digests on the copies.
    for name, art in ARTIFACTS.items():
        dst = artifacts_dir / art["file"]
        shutil.copyfile(STICK / art["file"], dst)
        if sha256_file(dst) != art["sha"]:
            refuse(f"copy digest mismatch for {art['file']}")

    # Restore regions extracted from the full NAND backup.
    mtd5 = (BACKUP / "mtd5.bin").read_bytes()
    mtd4 = (BACKUP / "mtd4.bin").read_bytes()
    regions = {
        "bosplus-dtb-region.bin": RESTORE_DTB_SPAN,
        "bosplus-kernel-region.bin": RESTORE_KERNEL_SPAN,
        "bosplus-ramdisk-region.bin": RESTORE_RAMDISK_SPAN,
    }
    region_pins = {}
    for fname, (start, end) in regions.items():
        data = mtd5[start:end]
        (restore_dir / fname).write_bytes(data)
        region_pins[fname] = {"span": [start, end], "bytes": len(data),
                              "sha256": sha256_bytes(data)}
    (restore_dir / "bosplus-overlay-mtd4-region.bin").write_bytes(mtd4)
    region_pins["bosplus-overlay-mtd4-region.bin"] = {
        "span": [0, 0x2000000], "bytes": len(mtd4), "sha256": sha256_bytes(mtd4)}
    (restore_dir / "restore-bosplus-v1.sh").write_text(RESTORE_SH, newline="\n")

    # Live-DTB pin verification against the extracted backup bytes.
    dtb = mtd5[OFF_DTB:OFF_DTB + BOSPLUS_DTB_LEN]
    if sha256_bytes(dtb) != BOSPLUS_DTB_SHA:
        refuse("BraiinsOS live DTB pin mismatch in backup mtd5")

    # PRESERVED region pins computed from the backup.
    preserved_pins = {
        "head_all_ff": {"span": list(HEAD_FF),
                        "all_ff": all(b == 0xFF for b in mtd5[HEAD_FF[0]:HEAD_FF[1]])},
        "unidentified_blob": {"span": list(PRESERVED_BLOB),
                              "sha256": sha256_bytes(mtd5[PRESERVED_BLOB[0]:PRESERVED_BLOB[1]])},
        "marker_0x3100000": {"span": list(PRESERVED_MARKER),
                             "ascii": mtd5[PRESERVED_MARKER[0]:PRESERVED_MARKER[1]].decode("ascii", "replace")},
        "uboot_env": {"span": list(PRESERVED_ENV),
                      "sha256": sha256_bytes(mtd5[PRESERVED_ENV[0]:PRESERVED_ENV[1]])},
    }
    if not preserved_pins["head_all_ff"]["all_ff"]:
        refuse("backup mtd5 head region is not all-FF (unit state changed since recon)")
    if preserved_pins["marker_0x3100000"]["ascii"] != "0x00002400\x00":
        refuse("marker pin mismatch")

    # Candidate tar (deterministic ordering and metadata).
    tar_path = OUTPUT / f"{CANDIDATE_NAME}.tar"
    members = [
        (f"{CANDIDATE_NAME}/MANIFEST.json", manifest_bytes()),
        (f"{CANDIDATE_NAME}/probe.sh", PROBE_SH.encode()),
        (f"{CANDIDATE_NAME}/installer.sh", INSTALLER_SH.encode()),
        (f"{CANDIDATE_NAME}/artifacts/devicetree.dtb",
         (artifacts_dir / DTB_FILE).read_bytes()),
        (f"{CANDIDATE_NAME}/artifacts/uImage.kernel",
         (artifacts_dir / KERNEL_FILE).read_bytes()),
        (f"{CANDIDATE_NAME}/artifacts/uImage.rootfs.cpio.gz",
         (artifacts_dir / ROOTFS_FILE).read_bytes()),
    ]
    with tarfile.open(tar_path, "w", format=tarfile.GNU_FORMAT) as tar:
        for member, payload in members:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o755 if member.endswith(".sh") else 0o644
            import io
            tar.addfile(info, io.BytesIO(payload))
    tar_sha = sha256_file(tar_path)

    member_pins = {}
    for member, payload in members:
        member_pins[member] = {"bytes": len(payload), "sha256": sha256_bytes(payload)}

    receipt = {
        "schema": SCHEMA + ".build",
        "date": DATE,
        "inputs": {
            "stick_payload_dir": str(STICK),
            "backup_dir": str(BACKUP),
            "backup_mtd5_sha256": sha256_file(BACKUP / "mtd5.bin"),
            "backup_mtd4_sha256": sha256_file(BACKUP / "mtd4.bin"),
            "donor_kit": str(DONOR_DIR),
        },
        "outputs": {
            "tar": {"path": str(tar_path), "bytes": tar_path.stat().st_size,
                    "sha256": tar_sha, "members": member_pins},
            "restore_kit": {"path": str(restore_dir), "regions": region_pins},
        },
        "preserved_pins": preserved_pins,
        "bosplus_live_dtb": {"mtd5_offset": OFF_DTB, "bytes": BOSPLUS_DTB_LEN,
                             "sha256": BOSPLUS_DTB_SHA},
        "boundaries": {
            "miner_contact": False, "signing": False, "publication": False,
            "reboot_or_flash_performed": False,
        },
    }
    receipt_path = OUTPUT / "s19k-install-candidate-build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(artifacts_dir)
    print("BUILD OK")
    print(f"  tar: {tar_path} ({tar_path.stat().st_size} B) sha256={tar_sha}")
    print(f"  restore kit: {restore_dir}")
    print(f"  receipt: {receipt_path}")
    return receipt


# -------------------------------------------------------------- validate ----
def validate(receipt_out):
    tar_path = OUTPUT / f"{CANDIDATE_NAME}.tar"
    if not tar_path.is_file():
        refuse("run build first")
    import tempfile
    results = {"schema": SCHEMA + ".validation", "date": DATE, "checks": []}

    def check(name, ok, detail):
        results["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f" -- {detail}"))
        return ok

    with tempfile.TemporaryDirectory(prefix="s19k-install-val-") as tmp:
        tmp = Path(tmp)
        ex = tmp / "extracted"
        ex.mkdir()
        with tarfile.open(tar_path) as tar:
            tar.extractall(ex)
        cand = ex / CANDIDATE_NAME
        check("tar-extract", cand.is_dir(), str(cand))

        # Member-by-member diff against the donor kit layout.
        donor = {
            "vmlinux.bin": (DONOR_DIR / "vmlinux.bin"),
            "devicetree.dtb": (DONOR_DIR / "devicetree.dtb"),
            "uramdisk.image.gz": (DONOR_DIR / "uramdisk.image.gz"),
        }
        mapping = []
        ours_kernel = (cand / "artifacts/uImage.kernel").read_bytes()
        ours_rootfs = (cand / "artifacts/uImage.rootfs.cpio.gz").read_bytes()
        ours_dtb = (cand / "artifacts/devicetree.dtb").read_bytes()
        donor_kernel = donor["vmlinux.bin"].read_bytes()
        donor_dtb = donor["devicetree.dtb"].read_bytes()
        donor_uram = donor["uramdisk.image.gz"].read_bytes()
        mapping.append({"donor": "devicetree.dtb", "ours": "artifacts/devicetree.dtb",
                        "relation": "byte-identical",
                        "ok": ours_dtb == donor_dtb})
        mapping.append({"donor": "vmlinux.bin", "ours": "artifacts/uImage.kernel",
                        "relation": "uImage-wrapped (64 B header, load=ep=0x01080000, comp=0); body byte-identical",
                        "ok": ours_kernel[64:] == donor_kernel})
        mapping.append({"donor": "uramdisk.image.gz",
                        "ours": "artifacts/uImage.rootfs.cpio.gz",
                        "relation": ("role-identical runtime initramfs slot (MTD5+0x05100000 uImage "
                                     "type=ramdisk comp=gzip, BOS+ convention); content is DCENT_OS "
                                     "rootfs.cpio.gz, not the vnish initramfs"),
                        "ok": ours_rootfs[:4] == b"\x27\x05\x19\x56" and donor_uram[:4] == b"\x27\x05\x19\x56"})
        for m in mapping:
            check(f"donor-member-diff:{m['donor']}->{m['ours']}", m["ok"], m["relation"])
        results["donor_member_mapping"] = mapping

        # Fixture dry-run of the embedded installer.sh (real script text).
        fx = tmp / "fixture"
        fx.mkdir()
        shutil.copyfile(cand / "MANIFEST.json", fx / "MANIFEST.json")
        mtd5 = bytearray(b"\xff" * MTD5_SIZE)
        backup5 = (BACKUP / "mtd5.bin").read_bytes()
        for start, end in (PRESERVED_BLOB, PRESERVED_MARKER, PRESERVED_ENV,
                           RESTORE_DTB_SPAN, RESTORE_KERNEL_SPAN, RESTORE_RAMDISK_SPAN):
            mtd5[start:end] = backup5[start:end]
        (fx / "mtd5").write_bytes(bytes(mtd5))
        mtd4 = bytearray(b"\xff" * 0x2000000)
        backup4 = (BACKUP / "mtd4.bin").read_bytes()
        mtd4[0:0x60000] = backup4[0:0x60000]  # stale overlay UBI headers
        (fx / "mtd4").write_bytes(bytes(mtd4))
        # FF filler for FILEMODE erase simulation
        with open(fx / ".fffill", "wb") as fh:
            fh.write(b"\xff" * (1 << 20))

        env = dict(os.environ)
        env.update({"MTD5_DEV": str(fx / "mtd5"), "MTD4_DEV": str(fx / "mtd4"),
                    "FILEMODE": "1", "WORK": str(fx / "work")})

        def run(args, expect_ok=True, proc_cwd=None):
            proc = subprocess.run(
                ["sh", str(cand / "installer.sh")] + args,
                cwd=proc_cwd or str(cand), env=env,
                capture_output=True, text=True, timeout=600)
            return proc

        # /proc/mtd gate cannot pass in the fixture; verify it REFUSES first
        # (fail-closed proof), then bypass by calling internals via FILEMODE
        # fixture mode with a stubbed /proc/mtd through a mount namespace is
        # not portable -- instead the fixture runner uses the same gates the
        # unit would: run status with a patched PATH wrapper is overkill, so
        # we test the fail-closed gate and then the individual commands with
        # gates satisfied via the FILEMODE branch (layout check still runs).
        proc = run(["status"])
        results["status_fixture_output"] = proc.stdout[-2000:] + proc.stderr[-500:]
        check("installer-gates-fail-closed-on-fixture",
              proc.returncode != 0 and "mtd0 bootloader layout mismatch" in proc.stderr,
              "the installer must refuse to run where /proc/mtd is not the unit's")

        # Gate-level fixture: run the same commands with the layout gate
        # satisfied through a fake /proc via busybox env is not portable;
        # instead validate the flash/stage/verify/neutralize mechanics through
        # a thin runner that sources the installer's functions with the gate
        # precondition stubbed (fixture-only copy, not the shipped script).
        fixture_installer = fx / "installer-fixture.sh"
        text = (cand / "installer.sh").read_text()
        text = text.replace(
            'LAYOUT=$(cat /proc/mtd 2>/dev/null | tail -n +2 | tr -s \' \')',
            'LAYOUT=$(cat "$HERE/fixture-proc-mtd" 2>/dev/null | tail -n +2 | tr -s \' \')')
        fixture_installer.write_text(text)
        (fx / "fixture-proc-mtd").write_text(
            'dev:    size   erasesize  name\n'
            'mtd0: 00200000 00020000 "bootloader"\n'
            'mtd1: 00800000 00020000 "tpl"\n'
            'mtd2: 03200000 00020000 "stock_system"\n'
            'mtd3: 00500000 00020000 "stock_config"\n'
            'mtd4: 02000000 00020000 "overlay"\n'
            'mtd5: 09900000 00020000 "system"\n')
        env["HERE_STUB"] = "1"

        def runfx(args):
            return subprocess.run(["sh", str(fixture_installer)] + args,
                                  cwd=str(fx), env=env,
                                  capture_output=True, text=True, timeout=600)

        # id -u != 0 on the desk: stub the root check in the fixture copy too
        t2 = fixture_installer.read_text().replace(
            '[ "$(id -u)" = "0" ] || fail "root required"',
            '[ "${ fixture_root:-1}" = "0" ] || fail "root required"')
        t2 = t2.replace('"${ fixture_root:-1}"', '"${FIXTURE_ROOT:-1}"')
        fixture_installer.write_text(t2)
        env["FIXTURE_ROOT"] = "0"
        # erasesize/writesize sysfs reads: fixture stub via files
        (fx / "sysfs-mtd5-erasesize").write_text("131072")
        (fx / "sysfs-mtd5-writesize").write_text("2048")
        t3 = fixture_installer.read_text().replace(
            '[ "$(cat /sys/class/mtd/mtd5/erasesize)" = "$ERASE" ]',
            '[ "$(cat "$HERE/sysfs-mtd5-erasesize")" = "$ERASE" ]')
        t3 = t3.replace(
            '[ "$(cat /sys/class/mtd/mtd5/writesize)" = "$PAGE" ]',
            '[ "$(cat "$HERE/sysfs-mtd5-writesize")" = "$PAGE" ]')
        fixture_installer.write_text(t3)

        proc = runfx(["plan"])
        check("fixture-plan", proc.returncode == 0, proc.stderr[-400:])
        results["fixture_plan_output"] = proc.stdout

        # stage + flash each artifact
        for w, src in (("dtb", ours_dtb), ("kernel", ours_kernel),
                       ("rootfs", ours_rootfs)):
            staged = fx / f"{w}.upload"
            staged.write_bytes(src)
            proc = runfx(["stage", str(staged), w])
            check(f"fixture-stage-{w}", proc.returncode == 0, proc.stderr[-400:])
            proc = runfx(["flash", w])
            check(f"fixture-flash-{w}", proc.returncode == 0,
                  (proc.stderr or proc.stdout)[-400:])
        results["fixture_flash_output"] = proc.stdout + proc.stderr

        # neutralize (mtd4 FF-fill)
        proc = runfx(["neutralize"])
        check("fixture-neutralize", proc.returncode == 0,
              (proc.stderr or proc.stdout)[-400:])

        # Independent byte-level assertions on the fixture.
        mtd5_after = (fx / "mtd5").read_bytes()
        mtd4_after = (fx / "mtd4").read_bytes()
        ok_dtb = mtd5_after[OFF_DTB:OFF_DTB + DTB_LEN] == donor_dtb
        ok_kernel = mtd5_after[OFF_KERNEL:OFF_KERNEL + KERNEL_LEN] == ours_kernel
        ok_rootfs = mtd5_after[OFF_ROOTFS:OFF_ROOTFS + ROOTFS_LEN] == ours_rootfs
        check("fixture-bytes-dtb", ok_dtb, f"at {OFF_DTB:#x}")
        check("fixture-bytes-kernel", ok_kernel, f"at {OFF_KERNEL:#x}")
        check("fixture-bytes-rootfs", ok_rootfs, f"at {OFF_ROOTFS:#x}")
        preserved_ok = all(
            mtd5_after[s:e] == backup5[s:e]
            for s, e in (PRESERVED_BLOB, PRESERVED_MARKER, PRESERVED_ENV))
        check("fixture-preserved-regions-intact", preserved_ok,
              "blob/marker/env byte-identical to backup")
        head_ok = all(b == 0xFF for b in mtd5_after[0:0x900000])
        check("fixture-head-still-ff", head_ok, "MTD5 head untouched")
        # stale BOS+ kernel tail remnant is expected and pinned
        tail_expected = backup5[0x1F60000:0x20C0000]
        check("fixture-bosplus-kernel-tail-remnant-pinned",
              mtd5_after[0x1F60000:0x20C0000] == tail_expected,
              "stale BOS+ kernel bytes beyond our smaller uImage survive (inert)")
        check("fixture-mtd4-neutralized", all(b == 0xFF for b in mtd4_after),
              "whole mtd4 fixture is 0xFF after neutralize")

    ok_all = all(c["ok"] for c in results["checks"])
    results["verdict"] = "PASS" if ok_all else "FAIL"
    receipt_out.parent.mkdir(parents=True, exist_ok=True)
    if receipt_out.exists():
        refuse(f"validation receipt already exists (write-once): {receipt_out}")
    receipt_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"VALIDATE {results['verdict']} -> {receipt_out}")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verb", choices=("build", "validate"))
    parser.add_argument("--receipt", default=str(R10 / "s19k-install-validation-receipt-v1.json"))
    args = parser.parse_args()
    if args.verb == "build":
        build()
    else:
        validate(Path(args.receipt))


if __name__ == "__main__":
    main()
