#!/usr/bin/env python3
"""Refusal tests for the exact donor-to-native-boot producer."""
from pathlib import Path
import tempfile
import unittest

import prepare_release_am2_boot as boot


class ReleaseAm2BootTests(unittest.TestCase):
    def test_wrong_donor_refused_before_any_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            donor, output = root / "wrong.img", root / "boot"
            donor.write_bytes(b"not the exact pinned Braiins donor")
            with self.assertRaisesRegex(ValueError, "size/SHA256"):
                boot.prepare(donor, output, mkimage="must-not-execute")
            self.assertFalse(output.exists())

    def test_existing_output_preserved_before_donor_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "boot"
            output.mkdir()
            (output / "owner-file").write_bytes(b"preserve")
            with self.assertRaisesRegex(ValueError, "new boot output"):
                boot.prepare(root / "missing.img", output)
            self.assertEqual((output / "owner-file").read_bytes(), b"preserve")

    def test_wrong_kernel_cannot_receive_pinned_legacy_header(self):
        with self.assertRaisesRegex(ValueError, "exact admitted AM2 kernel"):
            boot.legacy_kernel(b"plausible Linux kernel")

    def test_template_is_existing_literal_sd_path_without_nand_mutation(self):
        source = boot.source_environment().decode()
        self.assertIn("root=/dev/mmcblk0p2 rootfstype=squashfs ro", source)
        self.assertIn("uenvcmd=load mmc 0 0x3FFFFC0 u-boot.img && go 0x4000000", source)
        for mutation in ("nand write", "nand erase", "saveenv", "fw_setenv"):
            self.assertNotIn(mutation, source)


if __name__ == "__main__":
    unittest.main()
