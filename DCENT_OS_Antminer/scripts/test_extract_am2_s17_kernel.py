#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("extract_am2_s17_kernel.py")
SPEC = importlib.util.spec_from_file_location("extract_am2_s17_kernel", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


WORKSPACE = Path(__file__).resolve().parents[3]
DONOR = WORKSPACE / ""


def _build_fit(root: Path, kernel: bytes, dtb: bytes) -> Path:
    root.mkdir()
    kernel_path = root / "kernel.bin"
    dtb_path = root / "s17.dtb"
    kernel_path.write_bytes(kernel)
    dtb_path.write_bytes(dtb)
    output = root / "s17.itb"
    subject.build_ubi_fit(kernel_path, dtb_path, output)
    return output


class S17DonorAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        if not DONOR.is_file():
            self.skipTest("exact held Braiins S17 SD donor is not present")

    def test_exact_disk_fit_kernel_dtb_and_boot_contract_admit(self) -> None:
        kernel, dtb, receipt = subject.admit_donor(DONOR)
        self.assertEqual(subject.DONOR_SHA256, receipt["donor"]["sha256"])
        self.assertEqual(subject.SOURCE_FIT_SHA256, receipt["source_fit"]["sha256"])
        self.assertEqual(subject.KERNEL_SHA256, subject.sha256_bytes(kernel))
        self.assertEqual(subject.DTB_SHA256, subject.sha256_bytes(dtb))
        self.assertEqual(subject.DTB_MODEL, receipt["source_fit"]["dtb"]["model"])
        self.assertEqual("mtd7/firmware1", receipt["uboot"]["firmware_slots"]["1"])
        self.assertEqual("mtd8/firmware2", receipt["uboot"]["firmware_slots"]["2"])
        self.assertFalse(receipt["authorization"]["stock_first_install"])
        self.assertFalse(receipt["authorization"]["flash"])

    def test_wrong_outer_image_hash_is_refused_before_partition_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "mutated.img"
            raw = bytearray(DONOR.read_bytes())
            raw[len(raw) // 2] ^= 1
            mutated.write_bytes(raw)
            with self.assertRaisesRegex(subject.AdmissionError, "size/SHA256"):
                subject.admit_donor(mutated)

    def test_wrong_dtb_model_is_refused_even_with_matching_test_hash(self) -> None:
        _kernel, dtb, _receipt = subject.admit_donor(DONOR)
        mutated = dtb.replace(
            b"Antminer S17 Miner Control Board", b"Antminer T17 Miner Control Board", 1
        )
        self.assertEqual(len(dtb), len(mutated))
        with mock.patch.object(
            subject, "DTB_SHA256", hashlib.sha256(mutated).hexdigest()
        ):
            with self.assertRaisesRegex(subject.AdmissionError, "DTB model mismatch"):
                subject._validate_dtb(mutated)

    def test_extract_is_exclusive_and_records_denied_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel"
            dtb = root / "s17.dtb"
            receipt = root / "receipt.json"
            result = subject.extract(DONOR, kernel, dtb, receipt)
            decoded = json.loads(receipt.read_text("ascii"))
            self.assertEqual(subject.SCHEMA, decoded["schema"])
            self.assertFalse(result["authorization"]["device_contact"])
            with self.assertRaisesRegex(subject.AdmissionError, "must all be absent"):
                subject.extract(DONOR, kernel, dtb, receipt)

    def test_exact_model_bound_fit_fits_23_usable_lebs(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            receipt = subject.verify_ubi_fit(fit)
        self.assertEqual(23 * 126_976, receipt["geometry"]["kernel_capacity_bytes"])
        self.assertEqual(subject.OUTPUT_FIT_SIZE, receipt["geometry"]["fit_bytes"])
        self.assertEqual(subject.OUTPUT_FIT_SHA256, receipt["fit"]["sha256"])
        self.assertEqual(74_868, receipt["geometry"]["margin_bytes"])
        self.assertTrue(receipt["geometry"]["fits"])
        self.assertGreater(receipt["geometry"]["margin_bytes"], 0)
        self.assertEqual(subject.DTB_MODEL, receipt["fit"]["dtb_model"])
        self.assertFalse(receipt["authorization"]["stock_first_install"])

    def test_wrong_fit_payload_hash_is_refused(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            raw = bytearray(fit.read_bytes())
            offset = raw.find(kernel)
            self.assertGreaterEqual(offset, 0)
            raw[offset + len(kernel) // 2] ^= 1
            bad = Path(directory) / "wrong-hash.itb"
            bad.write_bytes(raw)
            with self.assertRaisesRegex(subject.AdmissionError, "reproducible pin"):
                subject.verify_ubi_fit(bad)

    def test_wrong_fit_configuration_is_refused(self) -> None:
        kernel, dtb, _receipt = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            fit = _build_fit(Path(directory) / "fit", kernel, dtb)
            raw = bytearray(fit.read_bytes())
            offset = raw.rfind(b"kernel@1\0")
            self.assertGreaterEqual(offset, 0)
            raw[offset : offset + len(b"kernel@1")] = b"kernel@2"
            wrong_config = Path(directory) / "wrong-config.itb"
            wrong_config.write_bytes(raw)
            with mock.patch.object(
                subject, "OUTPUT_FIT_SHA256", hashlib.sha256(raw).hexdigest()
            ):
                with self.assertRaisesRegex(
                    subject.AdmissionError, "selects the wrong kernel"
                ):
                    subject.verify_ubi_fit(wrong_config)

    def test_canonical_builder_reproduces_exact_bytes_and_refuses_overwrite(self) -> None:
        kernel, dtb, _ = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _build_fit(root / "first", kernel, dtb)
            second = _build_fit(root / "second", kernel, dtb)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(subject.OUTPUT_FIT_SHA256, subject.sha256_bytes(first.read_bytes()))
            before = first.read_bytes()
            with self.assertRaisesRegex(subject.AdmissionError, "must be absent"):
                subject.build_ubi_fit(first.parent / "kernel.bin", first.parent / "s17.dtb", first)
            self.assertEqual(before, first.read_bytes())

    def test_canonical_builder_refuses_changed_real_inputs_before_output(self) -> None:
        kernel, dtb, _ = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, raw in (("kernel", kernel), ("dtb", dtb)):
                with self.subTest(input=label):
                    altered = bytearray(raw)
                    altered[len(altered) // 2] ^= 1
                    k, d, out = root / "kernel.bin", root / "s17.dtb", root / (label + ".itb")
                    k.write_bytes(bytes(altered) if label == "kernel" else kernel)
                    d.write_bytes(bytes(altered) if label == "dtb" else dtb)
                    with self.assertRaisesRegex(subject.AdmissionError, "exact pin"):
                        subject.build_ubi_fit(k, d, out)
                    self.assertFalse(out.exists())

    def test_cli_canonical_build_rechecks_actual_output(self) -> None:
        kernel, dtb, _ = subject.admit_donor(DONOR)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            k, d, out = root / "kernel.bin", root / "s17.dtb", root / "s17.itb"
            k.write_bytes(kernel)
            d.write_bytes(dtb)
            result = subprocess.run([sys.executable, "-B", str(Path(subject.__file__)),
                "build-fit", "--kernel", str(k), "--dtb", str(d), "--output", str(out)],
                check=False, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(subject.verify_ubi_fit(out), json.loads(result.stdout))

    def test_cli_extract_emits_machine_readable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(subject.__file__)),
                    "extract",
                    "--donor",
                    str(DONOR),
                    "--kernel-output",
                    str(root / "kernel"),
                    "--dtb-output",
                    str(root / "s17.dtb"),
                    "--receipt",
                    str(root / "receipt.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                subject.DONOR_SHA256, json.loads(result.stdout)["donor"]["sha256"]
            )


if __name__ == "__main__":
    unittest.main()
