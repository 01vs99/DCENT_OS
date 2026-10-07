#!/usr/bin/env python3
"""Audit actual AM3 rootfs bytes and optionally exercise their ARM DHCP stack.

The simulation boots a test-only x86 Linux guest with binfmt QEMU user emulation
for the original ARM image binaries. It runs only the archived S40network and
requires an actual DHCP ACK plus assigned address on isolated QEMU slirp.
This is userspace/network acceptance, not a board/kernel/boot-media qualification.
No artifact extraction, device access or external networking occurs on the host.
"""
import argparse
import gzip
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("network_archive_reader", SCRIPT / "release_runtime_exports.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
# An explicit read-only roster reuses the bounded newc parser; publication's
# default signed-runtime roster remains unchanged.
NETWORK_FILES = {"etc/init.d/S40network": 65536, "etc/network/interfaces": 65536,
                 "etc/dcentos/board_target": 128}


def read_archive(path):
    limit = 512 * 1024 * 1024
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("rootfs archive must be a bounded regular file")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("rootfs archive grew beyond its size bound")
    return reader.gunzip(raw)


def audit(raw, board):
    files = reader.cpio_files(raw, expected=NETWORK_FILES)
    if files["etc/dcentos/board_target"].decode().strip() != board:
        raise ValueError("rootfs board identity differs from selected producer")
    interfaces = files["etc/network/interfaces"].decode()
    if not re.search(r"(?m)^\s*iface\s+eth0\s+inet\s+dhcp\s*(?:#.*)?$", interfaces):
        raise ValueError("actual image does not configure eth0 DHCP")
    if not files["etc/init.d/S40network"].startswith(b"#!/bin/sh"):
        raise ValueError("image network startup is not the expected shell service")
    return files


def newc(entries):
    result = bytearray()
    for index, (name, mode, payload) in enumerate([*entries, ("TRAILER!!!", 0, b"")], 1):
        fields = [index, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name.encode()) + 1, 0]
        result.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
        result.extend(name.encode() + b"\0")
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(payload)
        result.extend(b"\0" * (-len(result) % 4))
    return bytes(result)


def dhcp_ack(pcap):
    if pcap[:4] != b"\xd4\xc3\xb2\xa1" or len(pcap) < 24:
        raise ValueError("missing little-endian Ethernet packet capture")
    if struct.unpack_from("<I", pcap, 20)[0] != 1:
        raise ValueError("unexpected packet link format")
    offset = 24
    while offset + 16 <= len(pcap):
        size = struct.unpack_from("<I", pcap, offset + 8)[0]
        packet = pcap[offset + 16:offset + 16 + size]
        offset += 16 + size
        if len(packet) < 42 or packet[12:14] != b"\x08\x00" or packet[23] != 17:
            continue
        udp = 14 + (packet[14] & 15) * 4
        if packet[udp:udp + 4] != b"\x00\x43\x00\x44":
            continue
        bootp = packet[udp + 8:]
        if len(bootp) < 240 or bootp[0] != 2 or bootp[236:240] != b"\x63\x82\x53\x63":
            continue
        options, index = bootp[240:], 0
        while index < len(options):
            kind = options[index]
            index += 1
            if kind == 255:
                break
            if kind == 0:
                continue
            if index >= len(options):
                break
            length = options[index]
            value = options[index + 1:index + 1 + length]
            index += 1 + length
            if kind == 53 and value == b"\x05":
                return ".".join(str(byte) for byte in bootp[16:20])
    raise ValueError("actual DHCP ACK was not observed")


def simulate(raw, board, kernel, modules):
    audit(raw, board)
    machine = "aarch64" if not board.startswith("am3-bb") else "arm"
    emulator = Path(shutil.which(f"qemu-{machine}-static") or "/missing-emulator")
    magic = r"\xb7\x00" if machine == "aarch64" else r"\x28\x00"
    init = f'''#!/sim/busybox sh
set -eu
/sim/busybox mount -t proc proc /proc
/sim/busybox mount -t sysfs sysfs /sys
/sim/busybox mount -t devtmpfs devtmpfs /dev
/sim/busybox mount -t tmpfs tmpfs /run
/sim/busybox mount -t tmpfs tmpfs /tmp
/sim/busybox mount -t tmpfs tmpfs /data
/sim/busybox insmod /sim/binfmt_misc.ko
/sim/busybox insmod /sim/e1000.ko
/sim/busybox mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
echo ':dcent-arm:M:18:{magic}:\\xff\\xff:/sim/qemu-user:F' > /proc/sys/fs/binfmt_misc/register
/bin/sh /etc/init.d/S40network start
count=0
while [ "$count" -lt 30 ]; do
  if /sim/busybox ip -4 addr show dev eth0 | /sim/busybox grep -q 'inet 10.0.2.15/'; then
    echo DCENT_AM3_DHCP_ASSIGNED
    /sim/busybox poweroff -f
  fi
  /sim/busybox sleep 1
  count=$((count + 1))
done
echo DCENT_AM3_DHCP_FAILED
/sim/busybox poweroff -f
'''.encode()
    overlay = newc([("sim", stat.S_IFDIR | 0o755, b""),
        ("sim/busybox", stat.S_IFREG | 0o755, Path("/usr/bin/busybox").read_bytes()),
        ("sim/qemu-user", stat.S_IFREG | 0o755, emulator.read_bytes()),
        ("sim/binfmt_misc.ko", stat.S_IFREG | 0o644, (modules / "kernel/fs/binfmt_misc.ko").read_bytes()),
        ("sim/e1000.ko", stat.S_IFREG | 0o644, (modules / "kernel/drivers/net/ethernet/intel/e1000/e1000.ko").read_bytes()),
        ("init", stat.S_IFREG | 0o755, init)])
    with tempfile.TemporaryDirectory(prefix="dcent-am3-dhcp-") as temporary:
        directory = Path(temporary)
        initrd, capture = directory / "initrd.gz", directory / "dhcp.pcap"
        initrd.write_bytes(gzip.compress(raw + overlay, mtime=0))
        command = ["qemu-system-x86_64", "-machine", "pc", "-accel", "tcg", "-m", "512", "-smp", "1",
            "-nodefaults", "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", "console=ttyS0 rdinit=/init panic=-1 net.ifnames=0 biosdevname=0",
            "-netdev", "user,id=net0,restrict=on", "-device", "e1000,netdev=net0",
            "-object", f"filter-dump,id=dhcp,netdev=net0,file={capture}"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if result.returncode or b"DCENT_AM3_DHCP_ASSIGNED" not in result.stdout:
            raise ValueError("AM3 network guest failed: " + result.stdout[-12000:].decode(errors="replace"))
        if dhcp_ack(capture.read_bytes()) != "10.0.2.15":
            raise ValueError("assigned address was not joined to actual DHCP ACK")


class NetworkAuditTests(unittest.TestCase):
    def fixture(self, *, dhcp=True, service=True):
        entries = [(name, stat.S_IFDIR | 0o755, b"") for name in ("etc", "etc/init.d", "etc/network", "etc/dcentos")]
        entries += [("etc/dcentos/board_target", stat.S_IFREG | 0o644, b"am3-s21\n"),
                    ("etc/network/interfaces", stat.S_IFREG | 0o644, b"auto eth0\niface eth0 inet " + (b"dhcp\n" if dhcp else b"static\n"))]
        if service:
            entries.append(("etc/init.d/S40network", stat.S_IFREG | 0o755, b"#!/bin/sh\n/sbin/ifup -a\n"))
        return newc(entries)

    def test_actual_archive_members_and_dhcp_declaration_required(self):
        self.assertIn("etc/init.d/S40network", audit(self.fixture(), "am3-s21"))
        for raw, board in [(self.fixture(service=False), "am3-s21"), (self.fixture(dhcp=False), "am3-s21"), (self.fixture(), "am3-bb-s19jpro")]:
            with self.assertRaises(ValueError):
                audit(raw, board)

    def test_console_claim_is_not_a_dhcp_ack(self):
        with self.assertRaises(ValueError):
            dhcp_ack(b"DCENT_AM3_DHCP_ASSIGNED")


if __name__ == "__main__":
    import sys
    if "--rootfs" not in sys.argv:
        unittest.main()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--rootfs", type=Path, required=True, help="actual producer rootfs.cpio.gz")
        parser.add_argument("--board-target", required=True)
        parser.add_argument("--simulate", action="store_true")
        parser.add_argument("--kernel", type=Path, default=Path("/boot/vmlinuz-5.15.0-181-generic"))
        parser.add_argument("--modules", type=Path, default=Path("/lib/modules/5.15.0-181-generic"))
        args = parser.parse_args()
        raw = read_archive(args.rootfs)
        audit(raw, args.board_target)
        if args.simulate:
            simulate(raw, args.board_target, args.kernel, args.modules)
        print(f"PASS {args.board_target}: actual rootfs DHCP paths" + (" and QEMU userspace DHCP ACK" if args.simulate else " (simulation not requested)"))
