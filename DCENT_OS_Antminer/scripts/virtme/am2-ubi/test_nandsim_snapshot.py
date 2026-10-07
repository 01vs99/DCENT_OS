"""Pure snapshot format/ABI negative tests; no debugger, VM or device opens."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import nandsim_snapshot as snapshot


def modeled_memory():
    btf = snapshot.Btf()
    integer = snapshot.Type("u32", 1, 4)
    wide = snapshot.Type("u64", 1, 8)
    pointer = snapshot.Type("", 2, 0)
    geometry = snapshot.Type("", 4, 32, tuple((name, tid, offset*8) for name, tid, offset in (
        ("totsz", 2, 0), ("pgsz", 1, 8), ("oobsz", 1, 12), ("pgnum", 1, 16),
        ("secsz", 1, 20), ("pgszoob", 1, 24))))
    chip = snapshot.Type("nand_chip", 4, 64, (("bbt", 3, 32*8),))
    ns = snapshot.Type("nandsim", 4, 256, (("chip", 5, 64*8), ("pages", 3, 128*8),
        ("geom", 4, 160*8), ("cfile", 3, 200*8)))
    btf.types.update({1: integer, 2: wide, 3: pointer, 4: geometry, 5: chip, 6: ns})
    schema = snapshot.Schema(btf, "1"*64, "2"*64, "3"*64, "4"*64, ".bss", 0, 112)
    base = 0xffff888000000000
    symbol, pointers, bbt_address = base + 0x1000, base + 0x200000, base + 0x400000
    first, second = base + 0x500000, base + 0x600000
    body = bytearray(256)
    struct.pack_into("<Q", body, 128, pointers)
    struct.pack_into("<Q6I", body, 160, 256*1024**2, 2048, 64, 131072, 131072, 2112, 0)
    struct.pack_into("<Q", body, 96, bbt_address)
    pointer_array = bytearray(131072*8)
    struct.pack_into("<Q", pointer_array, 7*8, first)
    struct.pack_into("<Q", pointer_array, 64*8, second)
    regions = {base: body, symbol: struct.pack("<Q", base + 112), pointers: pointer_array,
               bbt_address: b"\x03" + bytes(511), first: b"A"*2048 + b"B"*64, second: b"\xff"*2112}
    def read(address, count):
        for start, raw in regions.items():
            if start <= address and address + count <= start + len(raw):
                return bytes(raw[address-start:address-start+count])
        raise AssertionError("reader attempted memory outside modeled nandsim ownership")
    return schema, read, symbol, regions, base


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "flash"
        self.schema, self.read, self.symbol, self.regions, self.base = modeled_memory()

    def capture(self):
        return snapshot.snapshot(self.schema, self.read, nsmtd_address=self.symbol,
                                 output=self.output, boundary="rootfs:update:returned")

    def load(self):
        return snapshot.load_snapshot(self.output, kernel_sha256="1"*64, module_sha256="2"*64)

    def test_roundtrip_retains_allocation_erased_oob_and_bbt_without_neighbor_memory(self):
        meta = self.capture()
        loaded, allocation, pages, bbt = self.load()
        self.assertEqual(meta, loaded)
        self.assertEqual(meta["allocated_pages"], 2)
        self.assertEqual(meta["allocated_erased_pages"], 1)
        self.assertEqual(list(snapshot.allocated_pages(allocation, pages)),
                         [(7, b"A"*2048+b"B"*64), (64, b"\xff"*2112)])
        self.assertEqual(bbt, b"\x03" + bytes(511))
        self.assertEqual(allocation[0], 128)
        with self.assertRaises(snapshot.SnapshotError):
            self.capture()

    def test_cache_file_layout_is_refused_before_capture(self):
        struct.pack_into("<Q", self.regions[self.base], 200, self.base + 0x700000)
        with self.assertRaisesRegex(snapshot.SnapshotError, "cache-file"):
            self.capture()
        self.assertFalse(self.output.exists())

    def test_foreign_geometry_is_refused(self):
        struct.pack_into("<I", self.regions[self.base], 168, 4096)
        with self.assertRaisesRegex(snapshot.SnapshotError, "geometry"):
            self.capture()
        self.assertFalse(self.output.exists())

    def test_non_kernel_pointer_is_refused(self):
        struct.pack_into("<Q", self.regions[self.base], 128, 0x200000)
        with self.assertRaisesRegex(snapshot.SnapshotError, "kernel pointer"):
            self.capture()

    def test_interrupted_page_capture_has_no_completion_metadata(self):
        self.regions.pop(self.base + 0x600000)
        with self.assertRaises(AssertionError):
            self.capture()
        self.assertFalse((self.output / "snapshot.json").exists())
        with self.assertRaises(snapshot.SnapshotError):
            self.load()

    def test_every_retained_component_tamper_is_refused(self):
        self.capture()
        for name in ("allocation.bin", "pages.bin", "bbt.bin"):
            with self.subTest(name=name):
                path = self.output / name
                original = path.read_bytes()
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaises(snapshot.SnapshotError):
                    self.load()
                path.write_bytes(original)

    def test_foreign_kernel_or_module_cannot_replay(self):
        self.capture()
        for kernel, module in (("0"*64, "2"*64), ("1"*64, "0"*64)):
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.load_snapshot(self.output, kernel_sha256=kernel, module_sha256=module)

    def test_duplicate_metadata_and_orphan_pages_refuse(self):
        self.capture()
        path = self.output / "snapshot.json"
        original = path.read_text()
        path.write_text('{"schema":"forged",' + original[1:])
        with self.assertRaises(snapshot.SnapshotError):
            self.load()
        with self.assertRaises(snapshot.SnapshotError):
            list(snapshot.allocated_pages(bytes(16384), b"x"*2112))

    def test_ordinary_member_in_a_structure_with_other_bitfields_is_admitted(self):
        btf = snapshot.Btf()
        btf.types[1] = snapshot.Type("mtd_info", 4, 64)
        mixed = snapshot.Type("nand_chip", 4, 128,
                              (("base", 1, 32*8), ("flag", 1, 1 << 24)), True)
        self.assertEqual(btf.member(mixed, "base")[0], 32)
        with self.assertRaisesRegex(snapshot.SnapshotError, "bitfield"):
            btf.member(mixed, "flag")


if __name__ == "__main__":
    unittest.main()
