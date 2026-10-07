"""Exercise exact beta rootfs installation and rejection before mutation."""

import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import struct
import tomllib
import unittest

SCRIPT = Path(__file__).with_name("prepare_s9_variant_rootfs.py")
SPEC = importlib.util.spec_from_file_location("prepare_s9_variant", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PrepareVariantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "rootfs"
        (self.root / "etc/dcentos").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "etc/dcentos/board_target").write_text("am1-s9\n")
        (self.root / "etc/dcentrald.toml").write_text("original config")
        daemon = self.root / "usr/bin/dcentrald"
        daemon.write_bytes(b"unchanged current daemon fixture")
        daemon.chmod(0o755)

    def test_installs_actual_exact_policy_and_idle_config_preserving_daemon(self):
        for target in MODULE.TARGETS:
            with self.subTest(target=target):
                (self.root / "etc/dcentos/board_target").write_text("am1-s9\n")
                MODULE.prepare(self.root, target)
                config = tomllib.loads((self.root / "etc/dcentrald.toml").read_text(encoding="utf-8"))
                policy = tomllib.loads((self.root / "etc/dcentrald-experimental.toml").read_text(encoding="utf-8"))
                self.assertEqual((self.root / "etc/dcentos/board_target").read_text(), target + "\n")
                self.assertEqual(config["mining"]["model"], target.removeprefix("am1-"))
                self.assertFalse(config["mining"]["enabled"])
                self.assertFalse(config["mining"]["passthrough"])
                self.assertEqual(config["pool"]["url"], "")
                self.assertEqual(config["thermal"]["fan_max_pwm"], 30)
                self.assertEqual(policy["executable_asic_chip_ids"], [0x1387])
                self.assertEqual(policy["admission"]["experimental_opt_in_targets"], [target])
                self.assertTrue(policy["admission"]["acknowledge_experimental_hardware_risk"])
                self.assertEqual((self.root / "usr/bin/dcentrald").read_bytes(), b"unchanged current daemon fixture")

    def test_wrong_variant_refuses_before_config_write(self):
        for target in ("am1-s9", "am1-s9se", "am1-s9k", "am1-t9plus", "am2-s17p"):
            with self.assertRaises(ValueError):
                MODULE.prepare(self.root, target)
        self.assertEqual((self.root / "etc/dcentrald.toml").read_text(), "original config")

    def test_explicit_current_arm_binaries_replace_all_three_with_bound_hashes(self):
        binaries = Path(self.temp.name) / "binaries"
        binaries.mkdir()
        for index, name in enumerate(("dcentrald", "dcentos-init", "dcentos-discovery")):
            elf = bytearray(64)
            elf[:6] = b"\x7fELF\x01\x01"
            struct.pack_into("<H", elf, 18, 40)
            elf[-1] = index
            (binaries / name).write_bytes(elf)
        MODULE.prepare(self.root, "am1-s9j", binaries)
        receipt = json.loads((self.root / "etc/dcentos/native-runtime-inputs.json").read_text())
        for name in receipt:
            installed = self.root / ("sbin/init" if name == "dcentos-init" else "usr/bin/" + name)
            self.assertEqual(installed.read_bytes(), (binaries / name).read_bytes())
            self.assertEqual(receipt[name]["sha256"], hashlib.sha256(installed.read_bytes()).hexdigest())
        self.assertEqual((self.root / "etc/dcentos/dcentrald.sha256").read_text().strip(), receipt["dcentrald"]["sha256"])

    def test_foreign_binary_refuses_before_any_beta_identity_write(self):
        binaries = Path(self.temp.name) / "binaries"
        binaries.mkdir()
        (binaries / "dcentrald").write_bytes(b"wrong-architecture")
        with self.assertRaises(ValueError):
            MODULE.prepare(self.root, "am1-s9j", binaries)
        self.assertEqual((self.root / "etc/dcentos/board_target").read_text(), "am1-s9\n")
        self.assertEqual((self.root / "etc/dcentrald.toml").read_text(), "original config")

    def test_wrong_carrier_refuses_before_any_identity_write(self):
        (self.root / "etc/dcentos/board_target").write_text("am2-s19pro\n")
        with self.assertRaises(ValueError):
            MODULE.prepare(self.root, "am1-s9i")
        self.assertEqual((self.root / "etc/dcentrald.toml").read_text(), "original config")
        self.assertFalse((self.root / "etc/dcentrald-experimental.toml").exists())

    def test_persistent_pool_override_refuses_before_identity_write(self):
        (self.root / "data").mkdir()
        (self.root / "data/dcentrald.toml").write_text("stale persistent config")
        with self.assertRaises(ValueError):
            MODULE.prepare(self.root, "am1-s9j")
        self.assertEqual((self.root / "etc/dcentos/board_target").read_text(), "am1-s9\n")
        self.assertEqual((self.root / "etc/dcentrald.toml").read_text(), "original config")

    def test_legacy_builder_defaults_and_variant_handoff_remain_explicit(self):
        builder = SCRIPT.with_name("build_sd_image.sh").read_text(encoding="utf-8")
        wrapper = SCRIPT.with_name("build_sd_s9_variant.sh").read_text(encoding="utf-8")
        self.assertIn('DCENTOS_BUILDROOT_IMAGES:-$FIRMWARE_DIR/buildroot/output/images', builder)
        self.assertIn('DCENTOS_S9_BOARD_TARGET:-am1-s9', builder)
        self.assertIn('S9_SD_TARGET="$S9_BOARD_TARGET-sd-standalone"', builder)
        self.assertIn('DCENTOS_S9_BOARD_TARGET="$board_target"', wrapper)
        self.assertIn('--standalone --disk-image', wrapper)


if __name__ == "__main__":
    unittest.main()
