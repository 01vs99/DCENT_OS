#!/usr/bin/env python3
"""Behavior checks for exact C43 donor, private staging and boot observer."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("c43_image", Path(__file__).with_name("prepare_c43_sd_image.py"))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
ROOT_UUID = "d362a466-39dc-4208-b7fd-203de7d7ad4a"
DATA_UUID = "a970508d-8427-5998-a732-08c4de3afe1a"


class C43ImageTests(unittest.TestCase):
    def test_exact_held_boot_payload_and_foreign_or_corrupt_donor_refused(self):
        boot = (IMAGE.DONOR / "BOOT.bin").read_bytes()
        payload = IMAGE.extract_fpga(boot)
        self.assertEqual(len(payload), 2083744)
        self.assertEqual(payload[0x30:0x34], b"\x66\x55\x99\xaa")
        corrupt = bytearray(boot)
        corrupt[IMAGE.BITSTREAM_OFFSET + 0x100] ^= 1
        with self.assertRaises(ValueError):
            IMAGE.extract_fpga(bytes(corrupt))
        with self.assertRaises(ValueError):
            IMAGE.extract_fpga(payload)

    def test_boot_load_hash_verification_precedes_receipt_and_direct_sd_root(self):
        env = IMAGE.boot_environment()
        load = env["dcent_fpga_load"]
        for earlier, later in (("setenv verify yes", "imxtract"), ("cmp.b", "imxtract"), ("imxtract", "fpga load 0")):
            self.assertLess(load.index(earlier), load.index(later))
        self.assertIn("if run dcent_fpga_load; then setenv dcent_c43_load_completed 1", env["uenvcmd"])
        self.assertTrue(env["uenvcmd"].startswith("setenv dcent_c43_load_completed 0;"))
        self.assertIn("root=/dev/mmcblk0p2 ro rootwait rootfstype=ext2", env["dcent_bootargs"])
        self.assertIn("bootm 0x02000000 - 0x03000000", env["uenvcmd"])
        self.assertNotIn("saveenv", " ".join(env.values()))
        self.assertNotIn("nand", " ".join(env.values()))

    def fixture(self, directory):
        root = directory / "root"
        binaries = directory / "binaries"
        for relative in ("etc/dcentos", "etc/init.d", "usr/bin", "usr/local/bin", "sbin", "data", "root"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "etc/dcentos/board_target").write_text("am1-s9\n")
        (root / "usr/local/bin/dcentrald").write_bytes(b"old base runtime selected by S82")
        supervisor = IMAGE.PROJECT / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S82dcentrald"
        shutil.copyfile(supervisor, root / "etc/init.d/S82dcentrald")
        for name in ("S10modules", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
            (root / "etc/init.d" / name).write_text("old-source\n")
        binaries.mkdir()
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", elf, 18, 40)
        # Non-executable input-typing fixture; actual software qualification
        # separately inspects complete built ARM binaries and reviewed hashes.
        elf.extend(b"--c43-boot-cut-only")
        for name in ("dcentrald", "dcentos-init", "dcentos-discovery"):
            (binaries / name).write_bytes(elf)
        return root, binaries

    def test_exact_native_root_staging_has_own_defaults_storage_and_no_foreign_fan_fallback(self):
        for target in IMAGE.TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root, binaries = self.fixture(Path(temp))
                IMAGE.prepare_root(root, target, binaries, ROOT_UUID, IMAGE.DATA_UUIDS[target])
                self.assertEqual((root / "etc/dcentos/board_target").read_text().strip(), target)
                self.assertEqual((root / "etc/dcentos/c43-data-uuid").read_text().strip(), IMAGE.DATA_UUIDS[target])
                config = (root / "etc/dcentrald.toml").read_text()
                self.assertIn("frequency_mhz = 100", config)
                self.assertIn("voltage_mv = 8500", config)
                self.assertIn("enabled = false", config)
                self.assertIn("0x1393", (root / "etc/dcentrald-experimental.toml").read_text())
                for name in ("S10modules", "S15pic_boot", "S37board_setup", "S99upgrade", "S99verify"):
                    self.assertFalse((root / "etc/init.d" / name).exists())
                text = (root / "etc/init.d/S82dcentrald").read_text(encoding="utf-8")
                self.assertTrue((root / "usr/local/bin/dcentrald").samefile(root / "usr/bin/dcentrald"))
                self.assertEqual((root / "usr/local/bin/dcentrald").read_bytes(), (binaries / "dcentrald").read_bytes())
                self.assertEqual((root / "usr/bin/dcentrald").stat().st_nlink, 2)
                for name, data in IMAGE.current_dashboard().items():
                    self.assertEqual((root / "usr/share/dcentos-dashboard" / name).read_bytes(), data)
                if shutil.which("sh"):
                    # Execute the produced selector with preserved executable
                    # data and config; only the operator config may be selected.
                    data = root / "data"
                    (data / "dcentrald").write_text("#!/bin/sh\nexit 99\n")
                    (data / "dcentrald").chmod(0o755)
                    (data / "dcentrald.toml").write_text("preserved config\n")
                    selector = text.split("select_dcentrald_paths() {", 1)[1].split("\n}", 1)[0]
                    command = ["sh", "-c", "select_dcentrald_paths() {" + selector.replace("/data/", str(data) + "/")
                        + '\n}\nselect_dcentrald_paths\nprintf "%s\\n%s\\n" "$DAEMON" "$CONFIG"']
                    selected = subprocess.run(command, capture_output=True, text=True, check=True).stdout.splitlines()
                    self.assertEqual(selected, ["/usr/local/bin/dcentrald", str(data / "dcentrald.toml")])
                fallback = text.split("fan_safety_override() {", 1)[1]
                self.assertLess(fallback.index("am1-s9se|am1-s9k"), fallback.index("FAN_BASE + 0x10"))
                self.assertIn("C43 SD data ownership unavailable", text)
                self.assertIn('DROPBEAR_ARGS="-s"', (root / "etc/default/dropbear").read_text())
                self.assertTrue((root / "etc/dcentos/release-image").is_file())
                self.assertTrue((root / "etc/init.d/S46c43_ssh").is_file())
                early = (root / "etc/dcentos-early-init.sh").read_text()
                self.assertNotIn("devmem ", early)
                self.assertNotIn("ubiattach", early)
                self.assertIn("/dev/mmcblk0p3 /data", early)
                self.assertEqual(len(json.loads((root / "etc/dcentos/c43-runtime-inputs.json").read_text())), 3)

    def test_mismatched_dashboard_refuses_before_native_identity_change(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root, binaries = self.fixture(directory)
            dashboard = directory / "dashboard"
            dashboard.mkdir()
            for name, data in IMAGE.current_dashboard().items():
                (dashboard / name).write_bytes(data)
            (dashboard / "index.html.sha256").write_text("0" * 64 + "\n")
            with patch.object(IMAGE, "DASHBOARD", dashboard), self.assertRaisesRegex(ValueError, "do not match"):
                IMAGE.prepare_root(root, "am1-s9se", binaries, ROOT_UUID, DATA_UUID)
            self.assertEqual((root / "etc/dcentos/board_target").read_text(), "am1-s9\n")
            self.assertEqual((root / "usr/local/bin/dcentrald").read_bytes(), b"old base runtime selected by S82")

    def test_foreign_data_or_equal_root_uuid_refuses_before_staging(self):
        for root_uuid, data_uuid in ((ROOT_UUID, IMAGE.DATA_UUIDS["am1-s9k"]), (DATA_UUID, DATA_UUID)):
            with self.subTest(root_uuid=root_uuid, data_uuid=data_uuid), tempfile.TemporaryDirectory() as temp:
                root, binaries = self.fixture(Path(temp))
                with self.assertRaisesRegex(ValueError, "target/layout data UUID"):
                    IMAGE.prepare_root(root, "am1-s9se", binaries, root_uuid, data_uuid)
                self.assertEqual((root / "etc/dcentos/board_target").read_text(), "am1-s9\n")

    def test_wrong_root_or_binary_is_rejected_before_identity_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root, binaries = self.fixture(Path(temp))
            (binaries / "dcentrald").write_bytes(b"prior-or-foreign-binary")
            with self.assertRaises(ValueError):
                IMAGE.prepare_root(root, "am1-s9se", binaries, ROOT_UUID, DATA_UUID)
            self.assertEqual((root / "etc/dcentos/board_target").read_text(), "am1-s9\n")

    def test_old_valid_arm_binary_without_boot_cut_refuses_before_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            root, binaries = self.fixture(Path(temp))
            daemon = binaries / "dcentrald"
            daemon.write_bytes(daemon.read_bytes()[:64])
            with self.assertRaisesRegex(ValueError, "predates the required idle-boot"):
                IMAGE.prepare_root(root, "am1-s9se", binaries, ROOT_UUID, DATA_UUID)
            self.assertEqual((root / "etc/dcentos/board_target").read_text(), "am1-s9\n")

    def test_audited_am2_base_is_fully_recomposed_and_unlisted_base_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, binaries = self.fixture(Path(temp))
            (root / "etc/dcentos/board_target").write_text("am2-s19j\n")
            (root / "etc/dcentos/platform").write_text("zynq-bm3-am2\n")
            for relative in ("etc/default/dcentrald-am2-xil-env", "etc/dcentrald/xil_override.toml",
                             "etc/dcentos/rail_gpio", "etc/dcentos/psu_config", "etc/init.d/S81dcentos-xil-seed",
                             "etc/init.d/S10udevd", "etc/init.d/S11modules", "etc/init.d/S50telnet"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("foreign AM2 recipe\n")
            with self.assertRaises(ValueError):
                IMAGE.prepare_root(root, "am1-s9se", binaries, ROOT_UUID, DATA_UUID, "0" * 64)
            self.assertEqual((root / "etc/dcentos/board_target").read_text().strip(), "am2-s19j")
            IMAGE.prepare_root(root, "am1-s9se", binaries, ROOT_UUID, DATA_UUID, IMAGE.ADMITTED_AM2_BASE_SHA256)
            self.assertFalse((root / "etc/default/dcentrald-am2-xil-env").exists())
            self.assertFalse((root / "etc/dcentrald/xil_override.toml").exists())
            self.assertFalse((root / "etc/dcentos/rail_gpio").exists())
            self.assertFalse((root / "etc/dcentos/psu_config").exists())
            for name in ("S81dcentos-xil-seed", "S10udevd", "S11modules", "S50telnet"):
                self.assertFalse((root / "etc/init.d" / name).exists())
            supervisor = (root / "etc/init.d/S82dcentrald").read_text(encoding="utf-8")
            self.assertNotIn(". /etc/default/dcentrald-am2-xil-env", supervisor)
            self.assertIn("BOARD_TARGET=am1-s9se", (root / "etc/dcentrald-target.conf").read_text())
            self.assertEqual(json.loads((root / "etc/dcentos/c43-userspace-source.json").read_text())["source_image_sha256"], IMAGE.ADMITTED_AM2_BASE_SHA256)

    @unittest.skipUnless(shutil.which("mkimage"), "host mkimage unavailable")
    def test_actual_mkimage_fit_retains_exact_raw_fpga_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            IMAGE.prepare_boot(output)
            data = (output / "c43-fabric.itb").read_bytes()
            self.assertEqual(data[:4], b"\xd0\x0d\xfe\xed")
            self.assertIn(bytes.fromhex(IMAGE.BITSTREAM_SHA256), data)
            self.assertIn(IMAGE.extract_fpga((IMAGE.DONOR / "BOOT.bin").read_bytes()), data)
            self.assertEqual((output / "BOOT.BIN").read_bytes(), (IMAGE.DONOR / "BOOT.bin").read_bytes())
            before = IMAGE.fdt_properties((IMAGE.DONOR / "devicetree.dtb").read_bytes())
            after = IMAGE.fdt_properties((output / "devicetree.dtb").read_bytes())
            self.assertTrue(all(after[key] == value for key, value in before.items()))
            node = "/amba@0/watchdog@f8005000"
            self.assertEqual(after[node, "reg"], struct.pack(">II", 0xF8005000, 0x1000))
            self.assertEqual(after[node, "clocks"], struct.pack(">II", 2, 45))
            self.assertEqual(after[node, "reset-on-timeout"], b"")
            self.assertEqual(len(after) - len(before), 7)

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
    def test_actual_observer_rejects_stale_duplicate_failed_load_and_wrong_progdone(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = [root / name for name in ("board", "pin", "cmdline", "boot_id", "prog_done")]
            for path, value in zip(files, ("am1-s9se", IMAGE.BITSTREAM_SHA256, "", ROOT_UUID, "1")):
                path.write_text(value + "\n")
            output = root / "out"
            helper = IMAGE.OVERLAY / "usr/libexec/dcentos/c43-fabric-identity.sh"
            command = ['sh', '-c', '. "$1"; shift; dcent_c43_fabric_identity "$@"', 'test', str(helper), *map(str, files), str(output)]
            valid = f"root=/dev/mmcblk0p2 dcent.c43_load_completed=1 dcent.c43_sha256={IMAGE.BITSTREAM_SHA256}"
            files[2].write_text(valid)
            self.assertEqual(subprocess.run(command, check=False).returncode, 0)
            receipt = output / "c43-fabric.json"
            self.assertEqual(json.loads(receipt.read_text()), {"schema": 1, "boot_id": ROOT_UUID,
                "bitstream_sha256": IMAGE.BITSTREAM_SHA256, "load_completed": True, "prog_done": True})
            for bad in (valid + " dcent.c43_load_completed=1", valid.replace("completed=1", "completed=0"), valid.replace(IMAGE.BITSTREAM_SHA256, "0" * 64)):
                files[2].write_text(bad)
                self.assertNotEqual(subprocess.run(command, check=False).returncode, 0)
                self.assertFalse(receipt.exists())
            files[2].write_text(valid)
            files[4].write_text("0\n")
            self.assertNotEqual(subprocess.run(command, check=False).returncode, 0)
            self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
