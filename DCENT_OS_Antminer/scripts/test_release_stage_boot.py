#!/usr/bin/env python3
"""Run actual native boot staging with distinct path-bound input fixtures."""
from pathlib import Path
import tempfile
import unittest

import release_stage_boot as staging
from binary_build_receipt import ReceiptError
from source_closure import BM1396_NATIVE_INPUTS, BM1396_S17E_NATIVE_INPUTS


class BootStagingTests(unittest.TestCase):
    def test_each_bm1396_model_stages_only_its_exact_three_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            expected = {}
            for target, names in (("am2-t17e", BM1396_NATIVE_INPUTS), ("am2-s17e", BM1396_S17E_NATIVE_INPUTS)):
                expected[target] = {}
                for name in names:
                    path = snapshot / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    raw = (target + ":" + path.name).encode()
                    path.write_bytes(raw)
                    expected[target][path.name] = raw
            for target in expected:
                output = root / target
                staging.stage(target, snapshot, output)
                self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, expected[target])
                self.assertEqual(set(expected[target]), {"BOOT.bin", "uImage", "devicetree.dtb"})

    def test_s17e_never_falls_back_to_t17e_or_generic_am2_donor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            for name in (*BM1396_NATIVE_INPUTS, staging.AM2_S17_DONOR_RELATIVE_PATH):
                path = snapshot / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"wrong board input")
            with self.assertRaisesRegex(ReceiptError, "native boot snapshot input is missing"):
                staging.stage("am2-s17e", snapshot, root / "output")

    def test_existing_destination_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            marker = output / "keep"
            marker.write_bytes(b"existing")
            with self.assertRaisesRegex(ValueError, "destination must be absent"):
                staging.stage("am2-s17e", root / "absent-snapshot", output)
            self.assertEqual(marker.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
