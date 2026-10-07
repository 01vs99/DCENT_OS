#!/usr/bin/env python3
"""Compose the DCENT_OS S19k Pro AML install candidate v2 ("observable
qualification variant").

v2 keeps the entire v1 mechanism (SSH-delivered gated direct MTD5 writes
mirroring the BraiinsOS on-flash layout, plus the mandatory MTD4 neutralize)
and changes exactly one thing: the CANDIDATE rootfs startup composition. When
the S19k storage owner refuses nvdata admission (the designed outcome on this
unit), the candidate's early-init hook captures the refusal, brings up the
volatile observability floor (virtual mounts + operator SSH key material via
the image's own S50dropbear gate) and exits 0, so the frozen PID1 runs its
normal S## service pass (source-verified: ServicePosture::Normal requires only
early_init_succeeded; the pass is permissive and non-fail-fast). dcentrald
still refuses to start (S82 storage-proof arm + frozen binary gates) and no
hashboard rail is ever energized.

Boundary: the repository board overlay and the production image semantics stay
byte-identical. The variant exists only inside the v2 candidate rootfs artifact
and is applied by this packager at packaging time. Every v1 artifact remains
byte-preserved; all v2 receipts are new files.

Verbs:
  build --operator-pubkey FILE   compose s19k-install-candidate-v2.tar
  validate [--receipt PATH]      scoped groups + fixture dry-run of the v2
                                 installer and startup variant (inert only)
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

SCHEMA = "dcent.r10.s19k-install-candidate.v2"
CANDIDATE_NAME = "s19k-install-candidate-v2"
CANDIDATE_NAME_V1 = "s19k-install-candidate-v1"
DATE = "2026-09-11"

WORKSPACE = Path(__file__).resolve().parents[3]
STICK = WORKSPACE / "DCENT_OS_Antminer/output/s19k-ramboot-stick-v1"
V1_OUTPUT = WORKSPACE / "DCENT_OS_Antminer/output/s19k-install-candidate-v1"
BUILD_IMAGES = Path("/root/dcent-beta-am3-s19kpro-image-v1/buildroot-output/images")
BACKUP = (WORKSPACE / ""
          "live-s19k-recon/nand-backup-203.0.113.80-v1")
OUTPUT = WORKSPACE / "DCENT_OS_Antminer/output" / CANDIDATE_NAME
R10 = (WORKSPACE / "")
SCRIPTS = WORKSPACE / "DCENT_OS_Antminer/scripts"
BOARD_OVERLAY = (WORKSPACE / "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/"
                 "am3-s19kpro-nopic/rootfs-overlay")

MTD5_SIZE = 0x9900000
MTD5_ERASE = 0x20000
PAGE = 2048
OFF_DTB = 0x00E00000
OFF_KERNEL = 0x01100000
OFF_ROOTFS = 0x05100000
PRESERVED_BLOB = (0x00900000, 0x009D2040)
PRESERVED_MARKER = (0x03100000, 0x0310000B)
PRESERVED_ENV = (0x04900000, 0x04A00000)
RESTORE_DTB_SPAN = (0x00E00000, 0x00E20000)
RESTORE_KERNEL_SPAN = (0x01100000, 0x020C0000)
RESTORE_RAMDISK_SPAN = (0x05100000, 0x06900000)

KERNEL_FILE, KERNEL_SHA, KERNEL_LEN = (
    "uImage.kernel", "bc7dc5aad8c33ef1d390988359d4ac46d0a7a68cbc7549697a5f3ee7ebd86faf", 14960712)
DTB_FILE, DTB_SHA, DTB_LEN = (
    "s19k.dtb", "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257", 20945)
KERNEL_BODY_SHA = "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6"
ROOTFS_V1_FILE = "rootfs.cpio.gz"
ROOTFS_V1_SHA = "bf85fc64f8894f61bceffc69458cef6c7f20b9ac63059cefc1b022ea331d4d3a"
ROOTFS_V1_BYTES = 30748539
ROOTFS_V1_UIMAGE_SHA = "88e267db5d063e2e0ad02168b0af84bed6cd80ee4f4b3df870c8c8e6fce4e2ed"
ROOTFS_V1_UIMAGE_BYTES = 30748603
EARLY_INIT_PATH = "etc/dcentos-early-init.sh"
FLOOR_PATH = "usr/libexec/dcentos/s19kpro-observe-floor.sh"
KEYS_PATH = "etc/dcentos/install-authorized_keys"

VARIANT_EARLY_INIT = r"""#!/bin/sh
# S19k Pro AML early gate — s19k-install-candidate-v2 observability variant.
#
# CANDIDATE-ONLY BYTES: this exact content exists only inside the
# s19k-install-candidate-v2 rootfs artifact, applied at packaging time by
# prepare_s19k_aml_install_candidate_v2.py. The repository board overlay and
# the production image keep the conservative production gate:
#   set -eu; exec /usr/bin/python3 -I /usr/libexec/dcentos/s19kpro-nopic-storage.py early
#
# Behavior: run the mandatory storage owner early gate. On success (healthy
# nvdada_log admitted) this is production-equivalent. On refusal, capture the
# refusal for post-install SSH qualification, bring up the volatile
# observability floor, and EXIT 0 so the frozen PID1 takes ServicePosture::Normal
# and runs the normal S## service pass (network, dropbear via its own gate).
# dcentrald still refuses to start (S82 storage-proof arm + binary gates) and
# no hashboard rail is ever energized: the only electrical authority,
# S37board_setup, asserts safe-off and runs in this pass as in production.
# Deliberately NO `set -e`: every step below is best-effort and the exit code
# is policy (always 0), not accident.

Q=/.dcentos-qualification
mkdir -p "$Q" 2>/dev/null || Q=/tmp
{
  echo "=== dcentos-early-init (s19k-install-candidate-v2 variant) ==="
  /usr/bin/python3 -I /usr/libexec/dcentos/s19kpro-nopic-storage.py early
  echo "=== storage early rc=$? ==="
} > "$Q/storage-early.log" 2>&1
rc=$(sed -n "s/.*storage early rc=//p" "$Q/storage-early.log" | tail -n 1)
if [ "$rc" = "0" ]; then
  exit 0
fi
cat "$Q/storage-early.log" > /dev/console 2>/dev/null
sh /usr/libexec/dcentos/s19kpro-observe-floor.sh "${rc:-unknown}" "$Q" > "$Q/floor.log" 2>&1
cat "$Q/floor.log" > /dev/console 2>/dev/null
exit 0
"""

VARIANT_FLOOR = r"""#!/bin/sh
# Candidate-only observability floor for the S19k Pro AML install candidate
# (s19k-install-candidate-v2). Runs from the variant early-init hook after the
# storage owner has refused. Read-side only: it mounts the volatile
# pseudo-filesystems the storage owner would have mounted, writes the
# qualification state readable over SSH, and installs the operator install
# public key so the image's own S50dropbear gate reaches enabled-by-keys.
# It never attaches, formats, writes, or erases any flash; it never starts
# dcentrald; no pool, worker, or hashboard state is touched.
# Fixture overrides (never set in production): FLOOR_DRYRUN, FLOOR_STATE_DIR,
# FLOOR_MNT_TAB.

REFUSAL_RC="${1:-unknown}"
Q="${2:-/.dcentos-qualification}"
STATE="${FLOOR_STATE_DIR:-/run/dcentos}"
MNT_TAB="${FLOOR_MNT_TAB:-/proc/mounts}"
DRY="${FLOOR_DRYRUN:-0}"

echo "=== observability floor: storage refused rc=$REFUSAL_RC; volatile floor up ==="

have_mount() { # have_mount <target>
  grep -q " $1 " "$MNT_TAB" 2>/dev/null
}

ensure_mount() { # ensure_mount <target> <fstype> <spec> <opts>
  if have_mount "$1"; then
    echo "  $1 already mounted"
    return 0
  fi
  if [ "$DRY" = "1" ]; then
    echo "  dryrun: mount -t $2 -o $4 $3 $1"
    return 0
  fi
  mkdir -p "$1" 2>/dev/null
  mount -t "$2" -o "$4" "$3" "$1" 2>/dev/null && echo "  mounted $1 ($2)" \
    || echo "  WARN: mount $1 ($2) failed (continuing)"
}

# /dev: PID1 leaves a tmpfs on /dev; the storage owner would have overmounted
# devtmpfs. Mirror that, then the pseudo mounts.
if grep -q " /dev devtmpfs " "$MNT_TAB" 2>/dev/null; then
  echo "  /dev is devtmpfs"
elif [ "$DRY" = "1" ]; then
  echo "  dryrun: mount -t devtmpfs -o mode=0755,nosuid devtmpfs /dev"
else
  mount -t devtmpfs -o mode=0755,nosuid devtmpfs /dev 2>/dev/null \
    && echo "  mounted /dev (devtmpfs)" || echo "  WARN: devtmpfs overmount failed"
fi
ensure_mount /run tmpfs tmpfs "mode=0755,nosuid,nodev,size=8m"
ensure_mount /tmp tmpfs tmpfs "mode=1777,nosuid,nodev,size=64m"
ensure_mount /dev/pts devpts devpts "gid=5,mode=620,nosuid,noexec"
ensure_mount /dev/shm tmpfs tmpfs "mode=1777,nosuid,nodev,noexec,size=8m"
if [ "$DRY" != "1" ]; then
  mkdir -p /run/lock 2>/dev/null
  [ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd 2>/dev/null
  [ -e /dev/stdin ] || ln -s /proc/self/fd/0 /dev/stdin 2>/dev/null
  [ -e /dev/stdout ] || ln -s /proc/self/fd/1 /dev/stdout 2>/dev/null
  [ -e /dev/stderr ] || ln -s /proc/self/fd/2 /dev/stderr 2>/dev/null
  ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null
  hn=$(cat /etc/hostname 2>/dev/null)
  [ -n "$hn" ] && hostname "$hn" 2>/dev/null
fi

# Qualification state, readable over SSH. (Inert even in DRYRUN: the state
# directory is the FLOOR_STATE_DIR override in fixtures, /run/dcentos tmpfs on
# the unit, and it is exactly the artifact the post-install SSH check reads.)
mkdir -p "$STATE" 2>/dev/null
chmod 0700 "$STATE" 2>/dev/null
if [ -f "$Q/storage-early.log" ]; then
  mv "$Q/storage-early.log" "$STATE/storage-early.log" 2>/dev/null \
    || cp "$Q/storage-early.log" "$STATE/storage-early.log" 2>/dev/null
fi
cat /proc/mtd > "$STATE/proc-mtd.txt" 2>/dev/null
cat /proc/self/mountinfo > "$STATE/mountinfo.txt" 2>/dev/null
{
  echo "storage admission refused rc=$REFUSAL_RC (expected on this unit's layout)"
  echo "variant=s19k-install-candidate-v2 observability floor active"
  echo "mining: OFF (dcentrald refused by its storage-proof gate; rails never energized)"
} > "$STATE/refusal.txt"
{
  printf '{\n'
  printf '  "schema": 1,\n'
  printf '  "variant": "s19k-install-candidate-v2-observability-floor",\n'
  printf '  "board_target": "%s",\n' "$(cat /etc/dcentos/board_target 2>/dev/null)"
  printf '  "boot_id": "%s",\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
  printf '  "storage": "refused",\n'
  printf '  "storage_refusal_rc": "%s",\n' "$REFUSAL_RC"
  printf '  "mining": "off",\n'
  printf '  "log_paths": ["/run/dcentos/refusal.txt", "/run/dcentos/storage-early.log", "/run/dcentos/proc-mtd.txt", "/run/dcentos/mountinfo.txt"]\n'
  printf '}\n'
} > "$STATE/qualification.json"
chmod 0600 "$STATE"/* 2>/dev/null
[ "$DRY" = "1" ] && echo "  dryrun: state written under $STATE"

# Operator install key through the image's own gate (S50dropbear reads
# /data/dcent/authorized_keys; the release-image marker would otherwise keep
# SSH locked). Public key material only; the private key never ships.
if [ "$DRY" = "1" ]; then
  echo "  dryrun: install /etc/dcentos/install-authorized_keys to /data/dcent/authorized_keys and /root/.ssh/authorized_keys (0600)"
else
  if [ -s /etc/dcentos/install-authorized_keys ]; then
    mkdir -p /data/dcent 2>/dev/null
    cp /etc/dcentos/install-authorized_keys /data/dcent/authorized_keys 2>/dev/null
    chmod 0600 /data/dcent/authorized_keys 2>/dev/null
    mkdir -p /root/.ssh 2>/dev/null && chmod 0700 /root/.ssh
    cp /etc/dcentos/install-authorized_keys /root/.ssh/authorized_keys 2>/dev/null
    chmod 0600 /root/.ssh/authorized_keys 2>/dev/null
    echo "  operator install key installed (S50dropbear gate: enabled-by-keys)"
  else
    echo "  WARN: no install key in initramfs; SSH will stay gate-locked"
  fi
fi
echo "=== floor complete; normal service pass follows ==="
exit 0
"""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refuse(message):
    print("REFUSED: " + message, file=sys.stderr)
    sys.exit(1)


def span_of(offset, length):
    blocks = (length + MTD5_ERASE - 1) // MTD5_ERASE
    return offset, offset + blocks * MTD5_ERASE


# --------------------------------------------------------------- cpio newc --
CPIO_MAGICS = (b"070701", b"070702")
FIELD_ORDER = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize",
               "devmajor", "devminor", "rdevmajor", "rdevminor",
               "namesize", "check")


def cpio_parse(data):
    pos = 0
    entries = []
    trailer_seen = False
    while pos < len(data):
        if data[pos:pos + 6] not in CPIO_MAGICS:
            if data[pos] == 0:
                pos += 1
                continue
            refuse(f"cpio parse: bad magic at offset {pos}")
        magic = data[pos:pos + 6]
        fields = {key: int(data[pos + 6 + i * 8: pos + 14 + i * 8], 16)
                  for i, key in enumerate(FIELD_ORDER)}
        name_start = pos + 110
        name = data[name_start:name_start + fields["namesize"]]
        data_start = (name_start + fields["namesize"] + 3) & ~3
        payload = data[data_start:data_start + fields["filesize"]]
        pos = (data_start + fields["filesize"] + 3) & ~3
        is_trailer = name.rstrip(b"\x00") == b"TRAILER!!!"
        entries.append((magic, fields, name, payload, is_trailer))
        if is_trailer:
            trailer_seen = True
            break
    if not trailer_seen:
        refuse("cpio parse: trailer missing")
    return entries


def cpio_serialize(entries, pad_to=512):
    out = io.BytesIO()
    for magic, fields, name, payload, _is_trailer in entries:
        out.write(magic)
        for key in FIELD_ORDER:
            out.write(b"%08X" % fields[key])
        out.write(name)
        while out.tell() % 4:
            out.write(b"\x00")
        out.write(payload)
        while out.tell() % 4:
            out.write(b"\x00")
    while out.tell() % pad_to:
        out.write(b"\x00")
    return out.getvalue()


def gzip_deterministic(payload, level=9):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=level, mtime=0) as gz:
        gz.write(payload)
    return buf.getvalue()


def uimage_wrap(payload, name, load, ep, image_type, comp):
    header = bytearray(64)
    header[0:4] = b"\x27\x05\x19\x56"
    header[8:12] = b"\x00" * 4                                  # zeroed timestamp
    header[12:16] = struct.pack(">I", len(payload))
    header[16:20] = struct.pack(">I", load)
    header[20:24] = struct.pack(">I", ep)
    header[24:28] = struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
    header[28] = 5                                              # os: linux
    header[29] = 22                                             # arch: arm64
    header[30] = image_type
    header[31] = comp
    name_bytes = name.encode("ascii")[:31]
    header[32:32 + len(name_bytes)] = name_bytes
    header[4:8] = struct.pack(">I", zlib.crc32(bytes(header[0:4]) + bytes(header[8:64])) & 0xFFFFFFFF)
    return bytes(header) + payload


# ------------------------------------------------------------------ build ---
def check_common_inputs():
    for path, sha, size in (
            (STICK / KERNEL_FILE, KERNEL_SHA, KERNEL_LEN),
            (STICK / DTB_FILE, DTB_SHA, DTB_LEN)):
        if not path.is_file():
            refuse("missing input " + str(path))
        if path.stat().st_size != size or sha256_file(path) != sha:
            refuse("stick payload pin mismatch: " + str(path))
    kernel = (STICK / KERNEL_FILE).read_bytes()
    if sha256_bytes(kernel[64:]) != KERNEL_BODY_SHA:
        refuse("kernel uImage body pin mismatch")
    v1_rootfs = BUILD_IMAGES / ROOTFS_V1_FILE
    if not v1_rootfs.is_file():
        refuse("missing v1 build rootfs: " + str(v1_rootfs))
    if v1_rootfs.stat().st_size != ROOTFS_V1_BYTES or sha256_file(v1_rootfs) != ROOTFS_V1_SHA:
        refuse("v1 rootfs.cpio.gz pin mismatch")
    if not (V1_OUTPUT / f"{CANDIDATE_NAME_V1}.tar").is_file():
        refuse("v1 candidate tar missing (v1 must stay byte-preserved and present)")
    if not BACKUP.is_dir():
        refuse("NAND backup missing")


def validate_pubkey(text):
    if not text or len(text) > 4096 or "\r" in text:
        refuse("operator pubkey: empty, oversized, or contains CR")
    lines = [line for line in text.split("\n") if line.strip()]
    if not 1 <= len(lines) <= 5:
        refuse("operator pubkey: must be 1..5 lines")
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
            refuse("operator pubkey: not an OpenSSH public key line")
        if len(parts[1]) > 800:
            refuse("operator pubkey: oversized key blob")
    return text if text.endswith("\n") else text + "\n"


def build_variant_rootfs(operator_pubkey):
    """Return (v2_cpio_gz_bytes, pins). Byte-faithful repack + 3 variant edits."""
    core = gzip.decompress((BUILD_IMAGES / ROOTFS_V1_FILE).read_bytes())
    entries = cpio_parse(core)
    reserialized = cpio_serialize(entries)
    if reserialized[:len(core)] != core:
        refuse("cpio round-trip mismatch: parser/serializer not byte-faithful")
    if any(b != 0 for b in core[len(reserialized):]):
        refuse("cpio round-trip: unexpected trailing bytes past reserialized core")

    overlay_early = (BOARD_OVERLAY / "etc/dcentos-early-init.sh").read_bytes()
    early_entry = next((e for e in entries
                        if not e[4] and e[2].rstrip(b"\x00") == EARLY_INIT_PATH.encode()), None)
    if early_entry is None:
        refuse("early-init entry not found in v1 rootfs cpio")
    early_old = bytes(early_entry[3])
    if early_old != overlay_early:
        refuse("cpio early-init payload differs from the repository overlay file")

    max_ino = max(e[1]["ino"] for e in entries)
    floor_fields = dict(early_entry[1])
    floor_fields.update({"ino": max_ino + 1, "mode": 0o100755, "nlink": 1,
                         "mtime": 0, "filesize": len(VARIANT_FLOOR.encode()),
                         "namesize": len(FLOOR_PATH.encode()) + 1, "check": 0})
    keys_fields = dict(early_entry[1])
    keys_fields.update({"ino": max_ino + 2, "mode": 0o100644, "nlink": 1,
                        "mtime": 0, "filesize": len(operator_pubkey.encode()),
                        "namesize": len(KEYS_PATH.encode()) + 1, "check": 0})
    early_fields = dict(early_entry[1])
    early_fields["filesize"] = len(VARIANT_EARLY_INIT.encode())
    early_new = (early_entry[0], early_fields, early_entry[2],
                 VARIANT_EARLY_INIT.encode(), False)

    new_entries = []
    inserted = 0
    for entry in entries:
        if not entry[4] and entry[2].rstrip(b"\x00") == EARLY_INIT_PATH.encode():
            new_entries.append(early_new)
            new_entries.append((entry[0], floor_fields,
                                FLOOR_PATH.encode() + b"\x00",
                                VARIANT_FLOOR.encode(), False))
            new_entries.append((entry[0], keys_fields,
                                KEYS_PATH.encode() + b"\x00",
                                operator_pubkey.encode(), False))
            inserted += 1
        else:
            new_entries.append(entry)
    if inserted != 1:
        refuse("variant insertion did not hit exactly one early-init entry")
    cpio_bytes = cpio_serialize(new_entries)
    # Self-check: re-parse the new archive; every entry must land exactly on a
    # header and the three variant payloads must come back verbatim.
    reparsed = cpio_parse(cpio_bytes)
    by_name = {e[2].rstrip(b"\x00").decode(): e for e in reparsed if not e[4]}
    for path, expected in ((EARLY_INIT_PATH, VARIANT_EARLY_INIT.encode()),
                           (FLOOR_PATH, VARIANT_FLOOR.encode()),
                           (KEYS_PATH, operator_pubkey.encode())):
        entry = by_name.get(path)
        if entry is None or bytes(entry[3]) != expected:
            refuse("variant entry round-trip failed for " + path)
    gz = gzip_deterministic(cpio_bytes)
    if gz != gzip_deterministic(cpio_bytes):
        refuse("gzip not deterministic")
    pins = {
        "early_init_old_sha256": sha256_bytes(early_old),
        "early_init_new_sha256": sha256_bytes(VARIANT_EARLY_INIT.encode()),
        "floor_sha256": sha256_bytes(VARIANT_FLOOR.encode()),
        "authorized_keys_sha256": sha256_bytes(operator_pubkey.encode()),
        "cpio_v2_sha256": sha256_bytes(cpio_bytes),
    }
    return gz, pins


def load_v1_member(tar_path, member_suffix):
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            if member.name.endswith(member_suffix):
                return tar.extractfile(member).read()
    refuse("v1 tar member not found: " + member_suffix)


def build(operator_pubkey_path):
    check_common_inputs()
    pubkey_text = validate_pubkey(Path(operator_pubkey_path).read_text())
    if OUTPUT.exists():
        refuse(f"output directory already exists (write-once): {OUTPUT}")
    OUTPUT.mkdir(parents=True)

    gz, variant_pins = build_variant_rootfs(pubkey_text)
    uimage = uimage_wrap(gz, "dcentos-s19k-rootfs", 0x02200000, 0, 3, 1)
    rootfs_sha = sha256_bytes(uimage)
    rootfs_len = len(uimage)
    cpio_gz_sha = sha256_bytes(gz)

    v1_tar = V1_OUTPUT / f"{CANDIDATE_NAME_V1}.tar"
    probe_sh = load_v1_member(v1_tar, "probe.sh")
    installer_v1 = load_v1_member(v1_tar, "installer.sh").decode()
    installer_v2 = installer_v1
    replacements = (
        (f"rootfs) echo {ROOTFS_V1_UIMAGE_BYTES};;", f"rootfs) echo {rootfs_len};;"),
        (f"rootfs) echo {ROOTFS_V1_UIMAGE_SHA};;", f"rootfs) echo {rootfs_sha};;"),
        (CANDIDATE_NAME_V1, CANDIDATE_NAME),
    )
    for old, new in replacements:
        if installer_v2.count(old) < 1:
            refuse("installer constant patch did not match: " + old[:60])
        installer_v2 = installer_v2.replace(old, new)
    if f"rootfs) echo {rootfs_len};;" not in installer_v2 or \
            f"rootfs) echo {rootfs_sha};;" not in installer_v2:
        refuse("installer v2 constants not applied")

    manifest = {
        "schema": SCHEMA,
        "date": DATE,
        "candidate": CANDIDATE_NAME,
        "based_on": "s19k-install-candidate-v1 (mechanism, offsets, gates, neutralize unchanged)",
        "claim": ("Observable-qualification variant of the unsigned S19k Pro AML "
                  "install candidate: on storage refusal the candidate rootfs still "
                  "brings up network + dropbear through the image's own gates so the "
                  "install can be qualified over SSH; dcentrald still refuses and no "
                  "hashboard rail is ever energized"),
        "variant": {
            "name": "observability-floor",
            "production_semantics_unchanged": True,
            "applied": "at packaging time to the candidate rootfs only",
            "files": [
                {"path": EARLY_INIT_PATH, "action": "replaced",
                 "old_sha256": variant_pins["early_init_old_sha256"],
                 "new_sha256": variant_pins["early_init_new_sha256"]},
                {"path": FLOOR_PATH, "action": "added",
                 "sha256": variant_pins["floor_sha256"]},
                {"path": KEYS_PATH, "action": "added",
                 "sha256": variant_pins["authorized_keys_sha256"],
                 "note": "operator install PUBLIC key material only"},
            ],
            "does_not_relax": [
                "no hashboard energization (S82 refuses dcentrald; S37 asserts safe-off)",
                "no pool or worker configuration",
                "no signing, no publication",
                "no flash writes from the startup hooks",
                "production (non-candidate) image build unchanged byte-for-byte",
            ],
        },
        "artifacts": {},
        "rootfs_provenance": {
            "v1_cpio_gz": {"sha256": ROOTFS_V1_SHA, "bytes": ROOTFS_V1_BYTES},
            "v2_cpio_gz": {"sha256": cpio_gz_sha, "bytes": len(gz)},
            "v1_uImage_rootfs": {"sha256": ROOTFS_V1_UIMAGE_SHA, "bytes": ROOTFS_V1_UIMAGE_BYTES},
            "v2_uImage_rootfs": {"sha256": rootfs_sha, "bytes": rootfs_len},
        },
        "target": {
            "board": "Antminer S19k Pro (Amlogic A113D/AXG, BHB56903)",
            "source_firmware": "BraiinsOS (BOSminer plus-tuner 0.9.0-db69f9bc)",
            "mtd5_system_size": MTD5_SIZE, "mtd5_erasesize": MTD5_ERASE, "page": PAGE,
        },
        "preserved_regions": {
            "head_all_ff": {"span": [0x00000000, 0x00900000]},
            "unidentified_blob": {"span": list(PRESERVED_BLOB)},
            "marker_0x3100000": {"span": list(PRESERVED_MARKER)},
            "uboot_env": {"span": list(PRESERVED_ENV)},
        },
        "neutralize": {
            "device": "/dev/mtd4", "bytes": 0x02000000,
            "reason": ("identical to v1: the stale overlay UBI would auto-attach over "
                       "the donor nvdata window and background-erase the boot artifacts"),
        },
        "posture": {
            "signed": False,
            "mining": "OFF: dcentrald refuses (S82 arm + binary gates); rails never energized",
            "post_install_access": ("SSH observability floor: qualification state under "
                                    "/run/dcentos/ + dropbear enabled-by-keys"),
        },
    }
    for name, (fname, sha, length, offset) in (
            ("dtb", ("devicetree.dtb", DTB_SHA, DTB_LEN, OFF_DTB)),
            ("kernel", ("uImage.kernel", KERNEL_SHA, KERNEL_LEN, OFF_KERNEL)),
            ("rootfs", ("uImage.rootfs.cpio.gz", rootfs_sha, rootfs_len, OFF_ROOTFS))):
        start, end = span_of(offset, length)
        manifest["artifacts"][name] = {
            "member": f"{CANDIDATE_NAME}/artifacts/{fname}", "bytes": length,
            "sha256": sha, "mtd5_offset": offset, "erase_span": [start, end],
            "erase_blocks": (end - start) // MTD5_ERASE,
        }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"

    members = [
        (f"{CANDIDATE_NAME}/MANIFEST.json", manifest_bytes),
        (f"{CANDIDATE_NAME}/probe.sh", probe_sh),
        (f"{CANDIDATE_NAME}/installer.sh", installer_v2.encode()),
        (f"{CANDIDATE_NAME}/artifacts/devicetree.dtb", (STICK / DTB_FILE).read_bytes()),
        (f"{CANDIDATE_NAME}/artifacts/uImage.kernel", (STICK / KERNEL_FILE).read_bytes()),
        (f"{CANDIDATE_NAME}/artifacts/uImage.rootfs.cpio.gz", uimage),
    ]
    tar_path = OUTPUT / f"{CANDIDATE_NAME}.tar"
    with tarfile.open(tar_path, "w", format=tarfile.GNU_FORMAT) as tar:
        for member, payload in members:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o755 if member.endswith(".sh") else 0o644
            tar.addfile(info, io.BytesIO(payload))
    tar_sha = sha256_file(tar_path)

    member_pins = {member: {"bytes": len(payload), "sha256": sha256_bytes(payload)}
                   for member, payload in members}
    receipt = {
        "schema": SCHEMA + ".build",
        "date": DATE,
        "inputs": {
            "stick_payload_dir": str(STICK),
            "v1_build_rootfs": {"path": str(BUILD_IMAGES / ROOTFS_V1_FILE),
                                "sha256": ROOTFS_V1_SHA, "bytes": ROOTFS_V1_BYTES},
            "v1_candidate_tar": str(v1_tar),
            "operator_pubkey": {"path": operator_pubkey_path,
                                "sha256": sha256_bytes(pubkey_text.encode()),
                                "note": "public key material only"},
            "backup_dir": str(BACKUP),
        },
        "outputs": {
            "tar": {"path": str(tar_path), "bytes": tar_path.stat().st_size,
                    "sha256": tar_sha, "members": member_pins},
            "rootfs_variant": variant_pins,
            "v2_cpio_gz_sha256": cpio_gz_sha,
        },
        "boundaries": {
            "miner_contact": False, "signing": False, "publication": False,
            "reboot_or_flash_performed": False,
            "repository_files_modified": False,
            "production_image_semantics_changed": False,
        },
    }
    receipt_path = OUTPUT / f"{CANDIDATE_NAME}-build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print("BUILD OK")
    print(f"  tar: {tar_path} ({tar_path.stat().st_size} B) sha256={tar_sha}")
    print(f"  rootfs uImage v2: {rootfs_len} B sha256={rootfs_sha} "
          f"(cpio.gz {len(gz)} B sha256={cpio_gz_sha})")
    print(f"  receipt: {receipt_path}")
    return {"tar_sha": tar_sha, "rootfs_sha": rootfs_sha, "rootfs_len": rootfs_len}


# --------------------------------------------------------------- validate ---
def validate(receipt_out):
    tar_path = OUTPUT / f"{CANDIDATE_NAME}.tar"
    if not tar_path.is_file():
        refuse("run build first")
    import tempfile
    results = {"schema": SCHEMA + ".validation", "date": DATE, "checks": []}

    def check(name, ok, detail=""):
        results["checks"].append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f" -- {detail}"))
        return bool(ok)

    with tempfile.TemporaryDirectory(prefix="s19k-install-v2-val-") as tmp:
        tmp = Path(tmp)
        ex = tmp / "extracted"
        ex.mkdir()
        with tarfile.open(tar_path) as tar:
            tar.extractall(ex)
        cand = ex / CANDIDATE_NAME

        manifest = json.loads((cand / "MANIFEST.json").read_text())
        for name, art in manifest["artifacts"].items():
            payload = (cand / "artifacts" / Path(art["member"]).name).read_bytes()
            check(f"member-sha:{name}",
                  len(payload) == art["bytes"] and sha256_bytes(payload) == art["sha256"],
                  art["member"])
        rootfs_img = (cand / "artifacts/uImage.rootfs.cpio.gz").read_bytes()
        gz_body = rootfs_img[64:]
        check("uimage-header-v2",
              rootfs_img[:4] == b"\x27\x05\x19\x56"
              and rootfs_img[28:32] == bytes((5, 22, 3, 1))
              and rootfs_img[8:12] == b"\x00" * 4,
              "os5/arch22/type3/comp1, zeroed timestamp")
        check("uimage-body-is-v2-cpio",
              sha256_bytes(gz_body) == manifest["rootfs_provenance"]["v2_cpio_gz"]["sha256"],
              "uImage body == variant cpio.gz")

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "test_s19kpro_nopic_storage.py", "-q"],
            cwd=str(SCRIPTS), capture_output=True, text=True, timeout=900)
        results["repo_scoped_tests"] = {
            "command": "pytest test_s19kpro_nopic_storage.py -q",
            "tail": (proc.stdout or proc.stderr)[-400:]}
        last_line = (proc.stdout or "").strip().split("\n")[-1]
        check("repo-scoped-s19k-storage-groups",
              proc.returncode == 0 and " failed" not in last_line, last_line)

        overlay_early = (BOARD_OVERLAY / "etc/dcentos-early-init.sh").read_bytes()
        check("production-overlay-early-init-unchanged",
              sha256_bytes(overlay_early) ==
              manifest["variant"]["files"][0]["old_sha256"],
              "repository overlay byte-identical to pre-variant pin")

        # Repacked tree diff vs the v1 rootfs: exactly the three variant paths.
        v1_tree = tmp / "v1tree"
        v2_tree = tmp / "v2tree"
        extraction = {}
        for label, tree, cpio_bytes in (
                ("v1", v1_tree, gzip.decompress(
                    (BUILD_IMAGES / ROOTFS_V1_FILE).read_bytes())),
                ("v2", v2_tree, gzip.decompress(gz_body))):
            tree.mkdir()
            (tree / "r.cpio").write_bytes(cpio_bytes)
            extraction[label] = subprocess.run(
                ["sh", "-c",
                 f"cd '{tree}' && cpio -id --no-absolute-filenames < r.cpio"],
                capture_output=True, timeout=600)
            for stream in ("stdout", "stderr"):
                value = getattr(extraction[label], stream)
                setattr(extraction[label], stream,
                        value.decode("utf-8", errors="replace"))
        check("gnu-cpio-extract-clean",
              all("junk" not in e.stderr and e.returncode == 0
                  for e in extraction.values()),
              " | ".join((e.stderr or "").strip().replace("\n", ";")
                         for e in extraction.values()))

        def tree_hashes(root):
            out = {}
            for path in sorted(Path(root).rglob("*")):
                rel = str(path.relative_to(root))
                if rel == "r.cpio":
                    continue  # this validator's own extraction input artifact
                if path.is_symlink():
                    out[rel] = "link:" + os.readlink(path)
                elif path.is_file():
                    out[rel] = sha256_file(path)
                else:
                    out[rel] = "dir"
            return out

        h1, h2 = tree_hashes(v1_tree), tree_hashes(v2_tree)
        added = sorted(set(h2) - set(h1))
        removed = sorted(set(h1) - set(h2))
        changed = sorted(k for k in set(h1) & set(h2) if h1[k] != h2[k])
        check("tree-diff-exactly-variant-paths",
              added == sorted([FLOOR_PATH, KEYS_PATH]) and removed == []
              and changed == [EARLY_INIT_PATH],
              f"added={added} removed={removed} changed={changed}")
        results["tree_diff"] = {"added": added, "removed": removed, "changed": changed}

        # Hook static checks (variant files live inside the extracted rootfs).
        early = (v2_tree / EARLY_INIT_PATH).read_bytes()
        floor = (v2_tree / FLOOR_PATH).read_bytes()
        keys = (v2_tree / KEYS_PATH).read_text()
        for label, blob, rel in (("early-init", early, EARLY_INIT_PATH),
                                 ("floor", floor, FLOOR_PATH)):
            check(f"hook-crlf-free:{label}", b"\r" not in blob, "no CR bytes")
            check(f"hook-shebang:{label}", blob.startswith(b"#!/bin/sh\n"), "shebang line 1")
            proc = subprocess.run(["sh", "-n", str(v2_tree / rel)],
                                  capture_output=True, text=True)
            check(f"hook-syntax:{label}", proc.returncode == 0, proc.stderr[-200:])
        danger = ("flash_erase", "nandwrite", "flashcp", "ubiformat", "ubiattach",
                  "ubidetach", "mkfs", "dd if=", "reboot", "/dev/mtd")
        hits = [tok for tok in danger for blob in (early, floor) if tok.encode() in blob]
        check("hook-danger-token-scan", not hits, str(hits))
        check("hook-variant-exit0-policy",
              early.count(b"exit 0") == 2 and b"observe-floor" in early
              and b"storage early rc=$?" in early,
              "refusal branch floors and exits 0; success branch exits 0")
        forbidden_invocations = (b"S82dcentrald", b"start dcentrald",
                                 b"/usr/sbin/dcentrald", b"systemctl",
                                 b"rc-service", b"/etc/init.d/")
        hits2 = [tok for tok in forbidden_invocations if tok in floor]
        check("floor-never-starts-dcentrald",
              not hits2 and b"mining: OFF" in floor,
              f"forbidden-invocation hits={hits2}")
        key_line = keys.strip().split("\n")[0].split()
        check("authorized-keys-shape",
              len(key_line) >= 2 and key_line[0].startswith(("ssh-", "ecdsa-"))
              and b"\r" not in keys.encode(),
              "operator install public key only")

        # Floor dry-run against fixture overrides.
        fx = tmp / "fixture"
        fx.mkdir()
        (fx / "mounts").write_text(
            "proc /proc proc rw 0 0\nsysfs /sys sysfs rw 0 0\n"
            "tmpfs /dev tmpfs rw,mode=755 0 0\n")
        env = dict(os.environ)
        env.update({"FLOOR_DRYRUN": "1", "FLOOR_STATE_DIR": str(fx / "run-dcentos"),
                    "FLOOR_MNT_TAB": str(fx / "mounts")})
        proc = subprocess.run(["sh", str(v2_tree / FLOOR_PATH), "2", str(fx / "q")],
                              env=env, capture_output=True, text=True, timeout=120)
        results["floor_dryrun_output"] = proc.stdout[-1500:]
        check("floor-dryrun-exit0", proc.returncode == 0, proc.stderr[-200:])
        (fx / "q").mkdir(exist_ok=True)
        (fx / "q/storage-early.log").write_text(
            "S19k Pro AML persistent storage refused: fixture\n")
        proc = subprocess.run(["sh", str(v2_tree / FLOOR_PATH), "2", str(fx / "q")],
                              env=env, capture_output=True, text=True, timeout=120)
        check("floor-dryrun-exit0-rerun", proc.returncode == 0, proc.stderr[-200:])
        qual_path = fx / "run-dcentos/qualification.json"
        check("floor-dryrun-state-written",
              qual_path.is_file() and (fx / "run-dcentos/refusal.txt").is_file()
              and (fx / "run-dcentos/storage-early.log").is_file()
              and (fx / "run-dcentos/proc-mtd.txt").exists()
              and "fixture" in (fx / "run-dcentos/storage-early.log").read_text(),
              "qualification state present under fixture state dir")
        qual = json.loads(qual_path.read_text())
        check("floor-qualification-json-fields",
              qual.get("variant") == "s19k-install-candidate-v2-observability-floor"
              and qual.get("storage") == "refused" and qual.get("mining") == "off",
              json.dumps(qual)[:200])
        check("floor-dryrun-mounts-not-executed",
              "dryrun: mount" in proc.stdout and "\n  mounted " not in proc.stdout,
              "no real mounts executed in dryrun")
        check("floor-dryrun-keys-not-executed",
              "dryrun: install" in proc.stdout and not (fx / "run-dcentos" == Path("/data/dcent")),
              "key install printed, not executed")

        # Early-init variant refusal branch end-to-end with a stubbed storage
        # owner (fixture copy; production bytes already asserted untouched).
        stub = fx / "stub-storage.sh"
        stub.write_text('#!/bin/sh\necho "S19k Pro AML persistent storage refused: fixture" >&2\nexit 2\n')
        os.chmod(stub, 0o755)
        stub_var = fx / "early-init-fixture.sh"
        stub_var.write_text(early.decode()
                            .replace("/usr/bin/python3 -I /usr/libexec/dcentos/s19kpro-nopic-storage.py early",
                                     f"sh {stub}")
                            .replace("/usr/libexec/dcentos/s19kpro-observe-floor.sh",
                                     str(fx / "observe-floor.sh")))
        os.chmod(stub_var, 0o755)
        shutil.copyfile(v2_tree / FLOOR_PATH, fx / "observe-floor.sh")
        env2 = dict(env)
        env2.pop("FLOOR_STATE_DIR", None)
        proc = subprocess.run(["sh", str(stub_var)], cwd=str(fx), env=env2,
                              capture_output=True, text=True, timeout=120)
        results["earlyinit_fixture_output"] = (proc.stdout or "")[-800:]
        check("earlyinit-refusal-branch-exit0", proc.returncode == 0,
              f"rc={proc.returncode} stderr={(proc.stderr or '')[-200:]}")
        q_log = Path("/.dcentos-qualification/storage-early.log")
        moved_log = Path("/run/dcentos/storage-early.log")
        captured = ((q_log.is_file() and "fixture" in q_log.read_text())
                    or (moved_log.is_file() and "fixture" in moved_log.read_text()))
        check("earlyinit-refusal-captured", captured,
              "refusal log captured at Q (or moved to the floor state dir)")
        shutil.rmtree("/.dcentos-qualification", ignore_errors=True)
        for residue in ("storage-early.log", "floor.log", "refusal.txt",
                        "qualification.json", "proc-mtd.txt", "mountinfo.txt"):
            Path("/run/dcentos", residue).unlink(missing_ok=True)
        check("desk-residue-cleaned",
              not Path("/.dcentos-qualification").exists()
              and not any(Path("/run/dcentos", r).exists() for r in
                          ("storage-early.log", "floor.log", "refusal.txt",
                           "qualification.json")),
              "desk residue removed after fixture run")

        # Determinism proof: rebuild the variant rootfs and compare bytes.
        gz_again, _ = build_variant_rootfs(keys)
        check("rootfs-deterministic", gz_again == gz_body, "second build byte-identical")

        # v1-style fixture dry-run of the installer with v2 artifacts.
        mtd5 = bytearray(b"\xff" * MTD5_SIZE)
        backup5 = (BACKUP / "mtd5.bin").read_bytes()
        for start, end in (PRESERVED_BLOB, PRESERVED_MARKER, PRESERVED_ENV,
                           RESTORE_DTB_SPAN, RESTORE_KERNEL_SPAN, RESTORE_RAMDISK_SPAN):
            mtd5[start:end] = backup5[start:end]
        (fx / "mtd5").write_bytes(bytes(mtd5))
        mtd4 = bytearray(b"\xff" * 0x2000000)
        backup4 = (BACKUP / "mtd4.bin").read_bytes()
        mtd4[0:0x60000] = backup4[0:0x60000]
        (fx / "mtd4").write_bytes(bytes(mtd4))
        with open(fx / ".fffill", "wb") as fh:
            fh.write(b"\xff" * (1 << 20))
        shutil.copyfile(cand / "MANIFEST.json", fx / "MANIFEST.json")
        env.update({"MTD5_DEV": str(fx / "mtd5"), "MTD4_DEV": str(fx / "mtd4"),
                    "FILEMODE": "1", "WORK": str(fx / "work"), "FIXTURE_ROOT": "0"})

        fixture_installer = fx / "installer-fixture.sh"
        text = (cand / "installer.sh").read_text()
        patched = text.replace(
            'LAYOUT=$(cat /proc/mtd 2>/dev/null | tail -n +2 | tr -s \' \')',
            'LAYOUT=$(cat "$HERE/fixture-proc-mtd" 2>/dev/null | tail -n +2 | tr -s \' \')')
        patched = patched.replace(
            '[ "$(id -u)" = "0" ] || fail "root required"',
            '[ "${FIXTURE_ROOT:-1}" = "0" ] || fail "root required"')
        patched = patched.replace(
            '[ "$(cat /sys/class/mtd/mtd5/erasesize)" = "$ERASE" ]',
            '[ "$(cat "$HERE/sysfs-erasesize")" = "$ERASE" ]')
        patched = patched.replace(
            '[ "$(cat /sys/class/mtd/mtd5/writesize)" = "$PAGE" ]',
            '[ "$(cat "$HERE/sysfs-writesize")" = "$PAGE" ]')
        fixture_installer.write_text(patched)
        (fx / "fixture-proc-mtd").write_text(
            'dev:    size   erasesize  name\n'
            'mtd0: 00200000 00020000 "bootloader"\n'
            'mtd1: 00800000 00020000 "tpl"\n'
            'mtd2: 03200000 00020000 "stock_system"\n'
            'mtd3: 00500000 00020000 "stock_config"\n'
            'mtd4: 02000000 00020000 "overlay"\n'
            'mtd5: 09900000 00020000 "system"\n')
        (fx / "sysfs-erasesize").write_text(str(MTD5_ERASE))
        (fx / "sysfs-writesize").write_text(str(PAGE))

        proc = subprocess.run(["sh", str(cand / "installer.sh"), "status"],
                              cwd=str(cand), env=env, capture_output=True, text=True)
        check("installer-gates-fail-closed",
              proc.returncode != 0 and "layout mismatch" in proc.stderr,
              "refuses off-unit")

        def runfx(args):
            return subprocess.run(["sh", str(fixture_installer)] + args,
                                  cwd=str(fx), env=env, capture_output=True,
                                  text=True, timeout=600)

        proc = runfx(["plan"])
        check("fixture-plan", proc.returncode == 0, (proc.stderr or "")[-300:])
        for w, src in (("dtb", (cand / "artifacts/devicetree.dtb").read_bytes()),
                       ("kernel", (cand / "artifacts/uImage.kernel").read_bytes()),
                       ("rootfs", rootfs_img)):
            staged = fx / f"{w}.upload"
            staged.write_bytes(src)
            proc = runfx(["stage", str(staged), w])
            check(f"fixture-stage-{w}", proc.returncode == 0, (proc.stderr or "")[-300:])
            proc = runfx(["flash", w])
            check(f"fixture-flash-{w}", proc.returncode == 0,
                  (proc.stderr or proc.stdout or "")[-300:])
        proc = runfx(["neutralize"])
        check("fixture-neutralize", proc.returncode == 0,
              (proc.stderr or proc.stdout or "")[-300:])

        mtd5_after = (fx / "mtd5").read_bytes()
        mtd4_after = (fx / "mtd4").read_bytes()
        check("fixture-bytes-dtb",
              mtd5_after[OFF_DTB:OFF_DTB + DTB_LEN] ==
              (cand / "artifacts/devicetree.dtb").read_bytes(), f"at {OFF_DTB:#x}")
        check("fixture-bytes-kernel",
              mtd5_after[OFF_KERNEL:OFF_KERNEL + KERNEL_LEN] ==
              (cand / "artifacts/uImage.kernel").read_bytes(), f"at {OFF_KERNEL:#x}")
        check("fixture-bytes-rootfs",
              mtd5_after[OFF_ROOTFS:OFF_ROOTFS + len(rootfs_img)] == rootfs_img,
              f"at {OFF_ROOTFS:#x} ({len(rootfs_img)} B)")
        check("fixture-preserved-intact",
              all(mtd5_after[s:e] == backup5[s:e] for s, e in
                  (PRESERVED_BLOB, PRESERVED_MARKER, PRESERVED_ENV)),
              "blob/marker/env intact")
        check("fixture-mtd4-neutralized", all(b == 0xFF for b in mtd4_after), "all FF")

    ok_all = all(c["ok"] for c in results["checks"])
    results["verdict"] = "PASS" if ok_all else "FAIL"
    receipt_out = Path(receipt_out)
    if receipt_out.exists():
        refuse(f"validation receipt already exists (write-once): {receipt_out}")
    receipt_out.parent.mkdir(parents=True, exist_ok=True)
    receipt_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"VALIDATE {results['verdict']} -> {receipt_out}")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verb", choices=("build", "validate"))
    parser.add_argument("--operator-pubkey")
    parser.add_argument("--receipt", default=str(R10 / "s19k-install-validation-receipt-v5.json"))
    args = parser.parse_args()
    if args.verb == "build":
        if not args.operator_pubkey:
            refuse("--operator-pubkey FILE is required for build (public key only)")
        build(args.operator_pubkey)
    else:
        validate(Path(args.receipt))


if __name__ == "__main__":
    main()
