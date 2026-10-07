#!/usr/bin/env python3
"""Mutate the actual compiled recovery DTB; never access hardware."""
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

import build_am3_bbctrl_recovery_dtb as producer


ROOT = Path(__file__).resolve().parents[3]
DONOR = ROOT/""
ARTIFACT = ROOT/"DCENT_OS_Antminer/output/i02-recovery-artifacts-v4/devicetree.dtb"
NAND = "/ocp/gpmc@50000000/nand@0,0"


def encode(tree):
    """Independent minimal FDT encoder for structural fault injection."""
    strings, body, offsets = bytearray(), bytearray(), {}

    def padded(data):
        return data.ljust((len(data)+3)//4*4, b"\0")

    def node(path):
        name = "" if path == "/" else path.rsplit("/", 1)[1]
        body.extend(struct.pack(">I", 1)+padded(name.encode()+b"\0"))
        for key, value in tree[path].items():
            if key not in offsets:
                offsets[key] = len(strings)
                strings.extend(key.encode()+b"\0")
            body.extend(struct.pack(">III", 3, len(value), offsets[key])+padded(value))
        for child in tree:
            if child != "/" and (child.rsplit("/", 1)[0] or "/") == path:
                node(child)
        body.extend(struct.pack(">I", 2))

    node("/")
    body.extend(struct.pack(">I", 9))
    total = 56+len(body)+len(strings)
    return (struct.pack(">10I", 0xd00dfeed, total, 56, 56+len(body), 40,
                        17, 16, 0, len(strings), len(body))+bytes(16)+body+strings)


class DtbProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DONOR.is_file() or not ARTIFACT.is_file():
            raise unittest.SkipTest("held BBCtrl source and actual v4 compiled DTB required")
        with zipfile.ZipFile(DONOR) as source:
            cls.donor = source.read("devicetree.dtb")
        cls.recovery = ARTIFACT.read_bytes()

    def mutate(self, path, key, value):
        tree = producer.nodes(self.recovery)
        if value is None:
            del tree[path][key]
        else:
            tree[path][key] = value
        return encode(tree)

    def test_actual_artifact_and_reencoded_topology_pass(self):
        for image in (self.recovery, encode(producer.nodes(self.recovery))):
            report = producer.compare(self.donor, image)
            self.assertEqual(report["source_comparison"], "verified")
            self.assertFalse(report["mining_carrier_equivalence"])
            self.assertFalse(report["physical_boot_validated"])

    def test_each_partition_offset_is_bound_including_gap(self):
        tree = producer.nodes(self.recovery)
        parts = [(path, props) for path, props in tree.items() if path.startswith(NAND+"/") and "label" in props]
        self.assertEqual(len(parts), 12)
        for path, props in parts:
            start, size = struct.unpack(">II", props["reg"])
            with self.subTest(partition=props["label"]), self.assertRaisesRegex(ValueError, "partition range"):
                producer.compare(self.donor, self.mutate(path, "reg", struct.pack(">II", start+0x20000, size)))

    def test_factory_windows_read_only_and_only_target_windows_writable(self):
        tree = producer.nodes(self.recovery)
        for path, props in tree.items():
            if path.startswith(NAND+"/") and "label" in props:
                value = b"" if "read-only" not in props else None
                with self.subTest(partition=props["label"]), self.assertRaisesRegex(ValueError, "protection"):
                    producer.compare(self.donor, self.mutate(path, "read-only", value))

    def test_nand_controller_ecc_driver_and_pad_faults_refuse(self):
        tree = producer.nodes(self.recovery)
        pads = next(path for path in tree if path.endswith("/bb-recovery-nand"))
        changes = [(NAND, "ti,nand-ecc-opt", b"bch4\0"), (NAND, "reg", struct.pack(">3I", 1, 0, 0)),
                   (NAND, "compatible", b"wrong,nand\0"),
                   (NAND.rsplit("/", 1)[0], "ranges", struct.pack(">4I", 0, 0, 0x10000000, 0x10000000)),
                   (pads, "pinctrl-single,pins", bytes(len(tree[pads]["pinctrl-single,pins"])))]
        for path, key, value in changes:
            with self.subTest(property=key), self.assertRaises(ValueError):
                producer.compare(self.donor, self.mutate(path, key, value))

    def test_parent_address_shift_and_card_detect_controller_refuse(self):
        tree = producer.nodes(self.recovery)
        for alias in ("mmc0", "serial0"):
            path = tree["/aliases"][alias].rstrip(b"\0").decode()
            parent = path.rsplit("/", 1)[0]
            ranges = bytearray(tree[parent]["ranges"])
            struct.pack_into(">I", ranges, 4, struct.unpack_from(">I", ranges, 4)[0]+0x1000)
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                producer.compare(self.donor, self.mutate(parent, "ranges", bytes(ranges)))
        mmc = tree["/aliases"]["mmc0"].rstrip(b"\0").decode()
        handle = tree[mmc]["cd-gpios"][:4]
        gpio = next(path for path, props in tree.items() if props.get("phandle") == handle)
        with self.assertRaisesRegex(ValueError, "GPIO controller"):
            producer.compare(self.donor, self.mutate(gpio, "reg", struct.pack(">II", 0x100, 0x1000)))

    def test_hashboard_uart_enable_and_model_relabel_refuse(self):
        tree = producer.nodes(self.recovery)
        uart = tree["/aliases"]["serial1"].rstrip(b"\0").decode()
        with self.assertRaisesRegex(ValueError, "hashboard UART"):
            producer.compare(self.donor, self.mutate(uart, "status", b"okay\0"))
        with self.assertRaisesRegex(ValueError, "recovery identity"):
            producer.compare(self.donor, self.mutate("/", "model", b"BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0\0"))

    def test_unpinned_source_and_wrong_donor_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)/"linux.tar.xz"
            source.write_bytes(b"unreviewed source")
            with self.assertRaisesRegex(ValueError, "kernel.org"):
                producer.verify_linux_sources(source, Path(temporary), [])
        with self.assertRaisesRegex(ValueError, "source digest"):
            producer.compare(self.recovery, self.recovery)


if __name__ == "__main__":
    unittest.main()
