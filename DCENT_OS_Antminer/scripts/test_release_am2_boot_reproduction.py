#!/usr/bin/env python3
"""Offline reproduction of all ten native AM2 boot pins.

The producer's Phase-4 admission (drop1-20260919-4f5h9mgl) proved that the
fabric FIT pin is only reproducible with the pinned u-boot mkimage build; the
capsule container's apt u-boot-tools emits structurally different bytes. This
suite runs the exact donor-to-pins reproduction the producer runs, seconds
instead of a full cohort, and fails loud when the pinned tool is absent or
tampered (never skips).

The pinned binary is a Linux x86-64 ELF: this suite is meaningful on the
WSL/Linux gate hosts (blocking gates require Linux) and cannot pass on
Windows Python.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]
sys.path.insert(0, str(SCRIPTS))

import prepare_release_am2_boot as boot  # noqa: E402
import release_stage_boot as staging  # noqa: E402

DONOR = REPO / ""
MKIMAGE_REL = Path("u-boot-2026.04-mkimage/mkimage")
BUILD_IN_DOCKER = SCRIPTS / "build_in_docker.sh"
BUILD_INPUTS_MANIFEST = SCRIPTS / "build_inputs.manifest"


def pinned_mkimage() -> Path:
    """Resolve the pinned binary from its documented locations (never guess).

    The producer exports DCENT_TOOLCHAIN_LOCAL_DIR in Windows form
    ("D:/<workspace>/toolchain-cache"), which does not resolve under a WSL
    gate run — so both the env location and the repo-relative cache are
    candidates, and an env value that does not exist here is simply not used.
    Whichever candidate is selected still passes through the sha check below.
    """
    candidates = []
    base = os.environ.get("DCENT_TOOLCHAIN_LOCAL_DIR", "")
    if base:
        candidates.append(Path(base) / MKIMAGE_REL)
    candidates.append(REPO / "toolchain-cache" / MKIMAGE_REL)
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise AssertionError(
        "blocking prerequisite is missing: pinned mkimage "
        f"({MKIMAGE_REL}) under any of: " + ", ".join(str(c.parent) for c in candidates)
    )


class ReleaseAm2BootReproductionTests(unittest.TestCase):
    def test_pinned_mkimage_is_present_and_tamper_checked(self):
        mkimage = pinned_mkimage()
        observed = hashlib.sha256(mkimage.read_bytes()).hexdigest()
        self.assertEqual(observed, boot.MKIMAGE_PIN_SHA256,
                         "pinned mkimage sha256 mismatch (toolchain-cache tamper?)")

    def test_pin_constants_are_identical_across_all_three_files(self):
        shell = BUILD_IN_DOCKER.read_text(encoding="utf-8")
        manifest = BUILD_INPUTS_MANIFEST.read_text(encoding="utf-8")
        self.assertEqual(shell.count(boot.MKIMAGE_PIN_SHA256), 1,
                         "build_in_docker.sh must pin the same mkimage sha256 exactly once")
        self.assertIn(boot.MKIMAGE_PIN_SHA256, manifest,
                      "build_inputs.manifest must carry the same sha for provisioning")

    def test_all_ten_pins_reproduce_from_the_admitted_donor(self):
        self.assertTrue(DONOR.is_file() and not DONOR.is_symlink(),
                        f"blocking prerequisite is missing: AM2 donor {DONOR}")
        with tempfile.TemporaryDirectory(prefix=".am2-pin-repro-") as temporary:
            output = Path(temporary) / "boot"
            checked = boot.prepare(DONOR, output, mkimage=str(pinned_mkimage()))
            self.assertEqual(len(checked), 10)
            self.assertEqual(set(checked), set(boot.AM2_BOOT_PINS))
            self.assertTrue(output.is_dir())
            self.assertEqual({path.name for path in output.iterdir()}, set(checked))

    def test_wrong_mkimage_version_is_refused_before_building_anything(self):
        # sys.executable is a real, runnable subprocess whose -V output can
        # never equal the pinned u-boot version string.
        self.assertTrue(DONOR.is_file(), "AM2 donor required for the admission prefix")
        with tempfile.TemporaryDirectory(prefix=".am2-pin-refuse-") as temporary:
            output = Path(temporary) / "boot"
            with self.assertRaisesRegex(ValueError, "pinned mkimage"):
                boot.prepare(DONOR, output, mkimage=sys.executable)
            self.assertFalse(output.exists())

    def test_boot_staging_refuses_without_dcent_mkimage_env(self):
        # Behavioral negative for the producer's Phase-4 entry point: with
        # DCENT_MKIMAGE unset the AM2 lane must refuse before spawning the
        # boot producer (the donor path check is lstat-only, no donor read).
        self.assertTrue(DONOR.is_file(), "AM2 donor required at its pinned path")
        with tempfile.TemporaryDirectory(prefix=".am2-stage-refuse-") as temporary:
            output = Path(temporary) / "boot"
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DCENT_MKIMAGE", None)
                with self.assertRaisesRegex(ValueError, "DCENT_MKIMAGE"):
                    staging.stage("am2-s17p", REPO, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
