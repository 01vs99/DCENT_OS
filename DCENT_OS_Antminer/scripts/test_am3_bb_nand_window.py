#!/usr/bin/env python3
"""Execute the actual BB C primitive through a file-backed NAND syscall shim.

The shim is compiled only into this test binary. The production executable
cannot select it or redirect /dev, and no real NAND device is opened here.
"""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

if os.name == "posix":
    import fcntl

ROOT = Path(__file__).resolve().parent
SIZES = (0x20000, 0x20000, 0x20000, 0x20000, 0x1c0000, 0x20000,
         0x20000, 0x500000, 0x1400000, 0x200000, 0x200000, 0x6000000)
NAMES = ("spl", "spl_backup1", "spl_backup2", "spl_backup3", "u-boot",
         "bootenv", "fdt", "kernel", "root", "config", "sig", "nvdata")
OFFSETS = (0, 0x20000, 0x40000, 0x60000, 0x80000, 0x240000, 0x260000,
           0x280000, 0x800000, 0x1c00000, 0x1e00000, 0x2000000)


def physical_sysfs_fixture(root):
    gpmc = root/"sys/firmware/devicetree/base/ocp/gpmc@50000000"
    nand = gpmc/"nand@0,0"
    nand.mkdir(parents=True)
    (nand/"reg").write_bytes(bytes(12))
    (gpmc/"reg").write_bytes(struct.pack(">II", 0x50000000, 0x1000000))
    (gpmc/"ranges").write_bytes(struct.pack(">IIII", 0, 0, 0x8000000, 0x10000000))
    (gpmc/"compatible").write_bytes(b"ti,am3352-gpmc\0")
    controller = root/"sys/devices/platform/50000000.gpmc/omap2-nand.0"
    controller.mkdir(parents=True)
    (controller/"of_node").symlink_to(nand, target_is_directory=True)
    for index, offset in enumerate(OFFSETS):
        directory = root/f"sys/class/mtd/mtd{index}"
        (directory/"offset").write_text(str(offset)+"\n")
        (directory/"device").symlink_to(controller, target_is_directory=True)


def env_bytes(command):
    body = (b"ethaddr=02:00:00:00:00:79\0bootcmd=" + command + b"\0\0").ljust(0x20000-4,b"\0")
    return struct.pack("<I", zlib.crc32(body)) + body


@unittest.skipUnless(os.name == "posix" and shutil.which("gcc"), "Linux gcc required")
class BBNandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="bb-nand-c-test-")
        cls.binary = Path(cls.build.name) / "bb-fixture"
        for source, destination in [("am3_bb_nand_window.c", "bb-production"),
                                    ("test_am3_bb_nand_shim.c", "bb-fixture")]:
            subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(ROOT/"first_install"/source), "-o", str(Path(cls.build.name)/destination)],
                           check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bb-nand-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("dev", "proc", "sys/class/mtd", "etc/dcentos"):
            (self.root/directory).mkdir(parents=True, exist_ok=True)
        rows = ["dev: size erasesize name\n"]
        for index, (name, size) in enumerate(zip(NAMES, SIZES)):
            with (self.root/f"dev/mtd{index}").open("wb") as file:
                file.truncate(size)
            sysdir = self.root/f"sys/class/mtd/mtd{index}"
            sysdir.mkdir()
            (sysdir/"name").write_text(name+"\n")
            (sysdir/"dev").write_text(f"90:{index*2}\n")
            rows.append(f'mtd{index}: {size:08x} 00020000 "{name}"\n')
        (self.root/"proc/mtd").write_text("".join(rows))
        (self.root/"proc/mounts").write_text("rootfs / rootfs rw 0 0\nproc /proc proc rw 0 0\n")
        (self.root/"etc/dcentos/board_target").write_text("am3-bb-s19jpro\n")
        physical_sysfs_fixture(self.root)
        self.before = self.root/"before"
        self.after = self.root/"after"
        self.before.write_bytes(env_bytes(b"run original"))
        self.after.write_bytes(env_bytes(b"run dcent"))
        (self.root/"dev/mtd5").write_bytes(self.before.read_bytes())

    def run_tool(self, *args, fault=""):
        return subprocess.run([str(self.binary), *map(str,args)], capture_output=True, text=True,
            env=dict(os.environ, BB_FIXTURE_ROOT=str(self.root), BB_FAULT=fault), timeout=30)

    def events(self):
        path = self.root/"events"
        return path.read_text() if path.exists() else ""

    def replace(self, **kwargs):
        return self.run_tool("replace", "mtd5", self.before, self.after, **kwargs)

    def test_environment_commit_and_exact_restore(self):
        factory = {index: hashlib.sha256((self.root/f"dev/mtd{index}").read_bytes()).hexdigest()
                   for index in (0,4,6,7,8,9,10)}
        result = self.replace()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("readback_verified",result.stdout)
        self.assertEqual((self.root/"dev/mtd5").read_bytes(),self.after.read_bytes())
        result = self.run_tool("replace","mtd5",self.after,self.before)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/"dev/mtd5").read_bytes(),self.before.read_bytes())
        for index, digest in factory.items():
            self.assertEqual(hashlib.sha256((self.root/f"dev/mtd{index}").read_bytes()).hexdigest(),digest)
        self.assertTrue(all(" mtd5 " in line for line in self.events().splitlines()))

    def test_read_exact_and_no_clobber(self):
        output = self.root/"capture"
        result = self.run_tool("read","mtd5",output)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(output.read_bytes(),self.before.read_bytes())
        self.assertNotEqual(self.run_tool("read","mtd5",output).returncode,0)
        self.assertEqual(self.events(),"")

    def test_each_physical_offset_and_missing_metadata_refuse_capture_and_erase(self):
        for index, offset in enumerate(OFFSETS):
            path = self.root/f"sys/class/mtd/mtd{index}/offset"
            with self.subTest(index=index):
                path.write_text(str(offset+0x20000)+"\n")
                self.assertNotEqual(self.replace().returncode, 0)
                output = self.root/"must-not-capture"
                self.assertNotEqual(self.run_tool("read", "mtd5", output).returncode, 0)
                self.assertFalse(output.exists())
                path.write_text(str(offset)+"\n")
        # Explicitly reject the plausible but incorrect contiguous map.
        (self.root/"sys/class/mtd/mtd8/offset").write_text(str(0x780000)+"\n")
        self.assertNotEqual(self.replace().returncode, 0)
        (self.root/"sys/class/mtd/mtd8/offset").unlink()
        self.assertNotEqual(self.replace().returncode, 0)
        self.assertEqual(self.events(), "")

    def test_wrong_parent_or_controller_refuses_before_erase(self):
        link = self.root/"sys/class/mtd/mtd11/device"
        original = link.readlink()
        other = self.root/"sys/devices/other-nand"
        other.mkdir()
        (other/"of_node").symlink_to(original/"of_node", target_is_directory=True)
        link.unlink()
        link.symlink_to(other, target_is_directory=True)
        self.assertNotEqual(self.replace().returncode, 0)
        link.unlink()
        link.symlink_to(original, target_is_directory=True)
        node = original/"of_node"
        node.unlink()
        node.symlink_to(other, target_is_directory=True)
        self.assertNotEqual(self.replace().returncode, 0)
        self.assertEqual(self.events(), "")

    def test_changed_gpmc_register_window_or_nand_chip_select_refuses(self):
        base = self.root/"sys/firmware/devicetree/base/ocp/gpmc@50000000"
        for relative in ("reg", "ranges", "compatible", "nand@0,0/reg"):
            with self.subTest(property=relative):
                path = base/relative
                original = path.read_bytes()
                changed = bytearray(original)
                changed[0] ^= 1
                path.write_bytes(changed)
                self.assertNotEqual(self.replace().returncode, 0)
                path.write_bytes(original)
        self.assertEqual(self.events(), "")

    def test_reserved_capture_reuses_allocated_exact_size_without_truncation(self):
        output = self.root/"reserved"
        with output.open("xb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            os.posix_fallocate(handle.fileno(), 0, SIZES[5])
        before = output.stat()
        for _ in range(2):
            result = self.run_tool("read-reserved", "mtd5", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), self.before.read_bytes())
            self.assertEqual(output.stat().st_ino, before.st_ino)
            self.assertGreaterEqual(output.stat().st_blocks, before.st_blocks)
        output.write_bytes(b"wrong length")
        self.assertNotEqual(self.run_tool("read-reserved", "mtd5", output).returncode, 0)
        with output.open("wb") as handle:
            handle.truncate(SIZES[5])
        self.assertNotEqual(self.run_tool("read-reserved", "mtd5", output).returncode, 0)
        self.assertEqual(self.events(), "")

    def test_preserved_partitions_are_never_write_destinations(self):
        for index in set(range(12))-{5,11}:
            with self.subTest(index=index):
                self.assertNotEqual(self.run_tool("replace",f"mtd{index}",self.before,self.after).returncode,0)
        self.assertEqual(self.events(),"")

    def test_bad_block_geometry_crc_and_stale_backup_fail_before_erase(self):
        for fault in ("bad-block", "geometry"):
            with self.subTest(fault=fault):
                self.assertNotEqual(self.replace(fault=fault).returncode,0)
                self.assertEqual(self.events(),"")
        self.after.write_bytes(bytes(0x20000))
        self.assertNotEqual(self.replace().returncode,0)
        self.after.write_bytes(env_bytes(b"run dcent"))
        self.before.write_bytes(env_bytes(b"stale backup"))
        self.assertNotEqual(self.replace().returncode,0)
        self.assertEqual(self.events(),"")

    def test_competing_owner_and_symlink_payload_fail_before_erase(self):
        with (self.root/"dev/mtd5").open("rb") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result=self.replace()
            self.assertNotEqual(result.returncode,0)
            self.assertIn("owner busy",result.stderr)
        self.after.unlink()
        self.after.symlink_to(self.before)
        self.assertNotEqual(self.replace().returncode,0)
        self.assertEqual(self.events(),"")

    def test_active_root_mounted_destination_and_wrong_target_fail_before_erase(self):
        for mount in ("/dev/mtdblock11 / jffs2 rw 0 0\n", "overlay / overlay rw 0 0\n",
                      "rootfs / rootfs rw 0 0\n/dev/mtdblock11 /mnt jffs2 ro 0 0\n"):
            with self.subTest(mount=mount):
                (self.root/"proc/mounts").write_text(mount)
                self.assertNotEqual(self.replace().returncode,0)
        (self.root/"proc/mounts").write_text("rootfs / rootfs rw 0 0\n")
        (self.root/"etc/dcentos/board_target").write_text("am3-s19jpro-aml\n")
        self.assertNotEqual(self.replace().returncode,0)
        self.assertEqual(self.events(),"")

    def test_ubi_attachment_map_and_device_identity_fail_before_erase(self):
        directory=self.root/"sys/class/ubi/ubi0"
        directory.mkdir(parents=True)
        (directory/"mtd_num").write_text("11\n")
        self.assertNotEqual(self.replace().returncode,0)
        (directory/"mtd_num").unlink()
        (self.root/"sys/class/mtd/mtd5/dev").write_text("90:99\n")
        self.assertNotEqual(self.replace().returncode,0)
        (self.root/"sys/class/mtd/mtd5/dev").write_text("90:10\n")
        (self.root/"proc/mtd").write_text((self.root/"proc/mtd").read_text().replace('"root"','"unexpected"'))
        self.assertNotEqual(self.replace().returncode,0)
        self.assertEqual(self.events(),"")

    def test_erase_write_sync_and_readback_faults_never_report_success(self):
        for fault in ("erase", "write", "sync", "readback"):
            with self.subTest(fault=fault):
                (self.root/"dev/mtd5").write_bytes(self.before.read_bytes())
                result=self.replace(fault=fault)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn("readback_verified",result.stdout)
                self.assertTrue(all(" mtd5 " in line for line in self.events().splitlines()))

    def test_nvdata_partial_page_and_erased_tail_verified(self):
        with self.before.open("wb") as file:
            file.truncate(SIZES[11])
        payload=b"fixture-payload"*157
        self.after.write_bytes(payload)
        result=self.run_tool("replace","mtd11",self.before,self.after)
        self.assertEqual(result.returncode,0,result.stderr)
        with (self.root/"dev/mtd11").open("rb") as file:
            self.assertEqual(file.read(len(payload)),payload)
            self.assertEqual(file.read(4096),b"\xff"*4096)
        self.assertTrue(all(" mtd11 " in line for line in self.events().splitlines()))
        # A second transition catches corruption in the otherwise-erased tail.
        shutil.copyfile(self.root/"dev/mtd11",self.before)
        result=self.run_tool("replace","mtd11",self.before,self.after,fault="tail")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("erased tail differs",result.stderr)


if __name__ == "__main__":
    unittest.main()
