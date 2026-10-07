#!/usr/bin/env python3
"""Offline kernel producer admission and load-envelope tests; no kernel build."""
from pathlib import Path
import struct
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zlib

import build_am3_bb_recovery_kernel as producer


def fdt_fixture(*, root_model=producer.MODEL, shifted=False):
    # Independent flattened-tree encoder; fixture is not a bootable board DTB.
    strings = bytearray()
    structure = bytearray()
    offsets = {}
    def node(name, properties, children=()):
        structure.extend(struct.pack(">I", 1))
        raw = name.encode()+b"\0"
        structure.extend(raw.ljust((len(raw)+3)//4*4, b"\0"))
        for key, value in properties.items():
            if key not in offsets:
                offsets[key] = len(strings)
                strings.extend(key.encode()+b"\0")
            structure.extend(struct.pack(">III", 3, len(value), offsets[key]))
            structure.extend(value.ljust((len(value)+3)//4*4, b"\0"))
        for child in children:
            node(*child)
        structure.extend(struct.pack(">I", 2))
    partition_data = (
        ("spl", 0, 0x20000), ("spl_backup1", 0x20000, 0x20000),
        ("spl_backup2", 0x40000, 0x20000), ("spl_backup3", 0x60000, 0x20000),
        ("u-boot", 0x80000, 0x1c0000), ("bootenv", 0x240000, 0x20000),
        ("fdt", 0x260000, 0x20000), ("kernel", 0x280000, 0x500000),
        ("root", 0x800000, 0x1400000), ("config", 0x1c00000, 0x200000),
        ("sig", 0x1e00000, 0x200000), ("nvdata", 0x2000000, 0x6000000))
    partitions = [(f"partition@{i}", {"label": name.encode()+b"\0", "reg": struct.pack(">II",
                   offset+(0x20000 if shifted and i == 11 else 0), size)})
                  for i, (name, offset, size) in enumerate(partition_data)]
    gpmc = ("gpmc@50000000", {"compatible": b"ti,am3352-gpmc\0",
             "reg": struct.pack(">II", 0x50000000, 0x1000000),
             "ranges": struct.pack(">IIII", 0, 0, 0x8000000, 0x10000000)},
            [("nand@0,0", {"reg": bytes(12)}, partitions)])
    node("", {"model": root_model.encode()+b"\0", "compatible": b"ti,am335x-bone-black\0"},
         [("ocp", {}, [gpmc])])
    structure.extend(struct.pack(">I", 9))
    total = 56+len(structure)+len(strings)
    return struct.pack(">10I", 0xd00dfeed, total, 56, 56+len(structure), 40,
                       17, 16, 0, len(strings), len(structure))+bytes(16)+structure+strings


class KernelProducerTests(unittest.TestCase):
    def test_unreviewed_relabelled_or_generic_carrier_is_refused(self):
        with self.assertRaisesRegex(ValueError, "source digest"):
            producer.carrier_dtb(fdt_fixture())
        for model in ("TI AM335x BeagleBone", "TI AM335x BeagleBone BTM"):
            with self.subTest(model=model), self.assertRaisesRegex(ValueError, "carrier DTB"):
                producer.carrier_dtb(fdt_fixture(root_model=model))

    def test_reviewed_fixture_requires_exact_physical_partitions(self):
        for shifted in (False, True):
            data = fdt_fixture(shifted=shifted)
            with patch.object(producer, "REVIEWED_CARRIER_DTB_HASHES", frozenset({producer.sha(data)})):
                if shifted:
                    with self.assertRaisesRegex(ValueError, "physical partition"):
                        producer.carrier_dtb(data)
                else:
                    producer.carrier_dtb(data)

    def test_config_dependency_drop_is_detected(self):
        fragment = (Path(__file__).parent/"first_install/am3_bb_recovery_kernel.config").read_text()
        producer.verify_config(fragment, fragment)
        for symbol in ("CONFIG_SYSFS", "CONFIG_MTD_OF_PARTS", "CONFIG_MTD_NAND_OMAP2", "CONFIG_EXT4_FS"):
            with self.subTest(symbol=symbol), self.assertRaisesRegex(ValueError, symbol):
                producer.verify_config(fragment.replace(symbol+"=y", symbol+"=m"), fragment)
        self.assertEqual(producer.config_values("# CONFIG_MTD_PARTITIONED_MASTER is not set"),
                         {"CONFIG_MTD_PARTITIONED_MASTER": "n"})

    def test_modern_load_envelope_and_legacy_crcs(self):
        zimage = bytearray(128)
        struct.pack_into("<III", zimage, 36, 0x016f2818, 0, len(zimage))
        output = producer.legacy_kernel(bytes(zimage), bytes(1024))
        fields = struct.unpack(">7I4B32s", output[:64])
        self.assertEqual(fields[4:6], (0x80008000, 0x80008000))
        self.assertEqual(fields[1], zlib.crc32(output[:4]+bytes(4)+output[8:64]))
        self.assertEqual(fields[6], zlib.crc32(output[64:]))
        with self.assertRaisesRegex(ValueError, "load profile"):
            producer.legacy_kernel(bytes(zimage), bytes(0x2000001))
        with self.assertRaisesRegex(ValueError, "load profile"):
            producer.legacy_kernel(bytes(128), bytes(1024))

    def test_unpinned_source_refuses_without_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root/"source.tar.xz"
            archive.write_bytes(b"untrusted source")
            with self.assertRaisesRegex(ValueError, "kernel.org SHA256"):
                producer.build(archive, root/"missing.dtb", root/"output", plan_only=True)
            self.assertFalse((root/"output").exists())

    def test_kernel_internal_symlink_is_relative_to_its_parent_and_escapes_refuse(self):
        with tempfile.TemporaryDirectory() as root:
            member = tarfile.TarInfo("linux-5.4.242/arch/arm64/boot/dts/arm/vexpress-v2m-rs1.dtsi")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../../../arm/boot/dts/vexpress-v2m-rs1.dtsi"
            self.assertEqual(producer.source_filter(member, root).linkname, member.linkname)
            for target in ("/outside", "../../../../../../../../outside"):
                member.linkname = target
                with self.subTest(target=target), self.assertRaisesRegex(ValueError, "escapes"):
                    producer.source_filter(member, root)


if __name__ == "__main__":
    unittest.main()
