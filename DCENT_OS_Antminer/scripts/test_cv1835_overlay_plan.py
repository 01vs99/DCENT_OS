#!/usr/bin/env python3
"""Host tests for the fail-closed CV1835 overlay planner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PLANNER = ROOT / "cv1835_overlay_plan.py"

# Import without executing main.
sys.path.insert(0, str(ROOT))
import cv1835_overlay_plan as planner  # noqa: E402


class Cv1835OverlayPlanTests(unittest.TestCase):
    def test_in_process_plan_is_denied_without_payload(self) -> None:
        plan = planner.overlay_plan(["--payload", "firmware.bin", "--flash"])
        planner.assert_plan_is_denied(plan)
        self.assertEqual(plan["board_target"], "cv1835-s19jpro")
        self.assertEqual(plan["install_authorization"], "denied")
        self.assertIsNone(plan["payload"])
        self.assertFalse(plan["flash"])

    def test_cli_exits_unavailable_and_prints_json_denial(self) -> None:
        result = subprocess.run(
            [sys.executable, str(PLANNER), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, planner.EX_UNAVAILABLE)
        self.assertIn("not_implemented", result.stderr)
        plan = json.loads(result.stdout)
        planner.assert_plan_is_denied(plan)

    def test_payload_flash_flags_cannot_authorize_or_write_a_blob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "overlay.bin"
            denial = Path(tmp) / "plan.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(PLANNER),
                    "--payload",
                    str(payload),
                    "--flash",
                    "--execute",
                    "--output",
                    str(payload),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, planner.EX_UNAVAILABLE)
            self.assertFalse(payload.exists())
            self.assertIn("payload-shaped path", result.stderr)

            result = subprocess.run(
                [
                    sys.executable,
                    str(PLANNER),
                    "--payload",
                    str(payload),
                    "--output",
                    str(denial),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, planner.EX_UNAVAILABLE)
            self.assertFalse(payload.exists())
            self.assertTrue(denial.is_file())
            on_disk = json.loads(denial.read_text(encoding="utf-8"))
            planner.assert_plan_is_denied(on_disk)

    def test_source_has_no_storage_mutation_api(self) -> None:
        source = PLANNER.read_text(encoding="utf-8")
        for token in (
            "nandwrite",
            "flash_erase",
            "nanddump",
            "/dev/mtd",
            "/dev/mmc",
            "subprocess",
            "socket",
        ):
            self.assertNotIn(token, source)


class DeskNowDevopsPackagingTests(unittest.TestCase):
    """Sanity for the leftover DESK_NOW example-TOML / Docker / BB / prune items."""

    EXAMPLES = (
        ROOT.parent / "dcentrald" / "dcentrald.toml",
        ROOT.parent / "dcentrald" / "dcentrald_s19.toml",
        ROOT.parent / "dcentrald" / "dcentrald_stock.toml",
        ROOT.parent / "dcentrald" / "dcentrald_coldboot.toml",
    )
    BB_RECOVERY = (
        ROOT.parent
        / "br2_external_dcentos"
        / "board"
        / "beaglebone"
        / "am3-bb"
        / "rootfs-overlay"
        / "root"
        / "web"
        / "static"
        / "recovery.html"
    )
    DOCKERFILES = (
        ROOT / "docker" / "Dockerfile.dcentrald-test",
        ROOT.parent / "dcentrald" / "Dockerfile.cross",
    )
    PINNED_DIGEST = (
        "rust@sha256:3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207"
    )
    PRUNE = (
        ROOT.parent
        / "br2_external_dcentos"
        / "board"
        / "common"
        / "prune-runtime-research-tools.sh"
    )
    RELEASE_POSTURE = ROOT.parent / "scripts" / "lib" / "release_posture.sh"
    COMMON_FRAGMENT = (
        ROOT.parent / "br2_external_dcentos" / "configs" / "dcentos-common.fragment"
    )

    def _autotuner_section(self, text: str) -> str:
        parts = text.split("\n[")
        for part in parts:
            if part.startswith("autotuner]"):
                return part
        self.fail("missing [autotuner] section")
        return ""

    def _pool_section(self, text: str) -> str:
        parts = text.split("\n[")
        for part in parts:
            if part.startswith("pool]"):
                return part
        self.fail("missing [pool] section")
        return ""

    def test_example_tomls_match_crate_autotuner_defaults_and_stay_off(self) -> None:
        for path in self.EXAMPLES:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                autotuner = self._autotuner_section(text)
                self.assertIn("enabled = false", autotuner)
                self.assertNotIn("enabled = true", autotuner)
                self.assertIn("measurement_window_s = 6", autotuner)
                self.assertNotIn("measurement_window_s = 3", autotuner)
                self.assertIn('target_mode = "efficiency"', autotuner)

    def test_example_tomls_do_not_default_url_to_solo_ckpool(self) -> None:
        for path in self.EXAMPLES:
            with self.subTest(path=path.name):
                pool = self._pool_section(path.read_text(encoding="utf-8"))
                active_urls = [
                    line
                    for line in pool.splitlines()
                    if line.strip().startswith("url =")
                ]
                self.assertTrue(active_urls)
                for line in active_urls:
                    self.assertNotIn("solo.ckpool.org", line)
                self.assertIn("solo.ckpool.org", pool)
                self.assertIn("NOT a first-boot default", pool)

    def test_bb_recovery_html_is_static_rescue_with_fund_and_no_secrets(self) -> None:
        text = self.BB_RECOVERY.read_text(encoding="utf-8")
        self.assertIn("https://d-central.tech/fund/", text)
        self.assertIn("microSD", text)
        self.assertIn("115200", text)
        self.assertIn("Do not raw-write NAND", text)
        self.assertNotIn("miner:miner", text)
        self.assertNotIn("root:root", text)
        self.assertNotIn("root/dcentral", text)
        self.assertNotIn("password =", text.lower())
        self.assertNotRegex(text, r"(?m)^\s*nandwrite\b")
        self.assertNotRegex(text, r"(?m)^\s*flash_erase\b")

    def test_rust_dockerfiles_pin_1_90_0_digest_not_floating_tags(self) -> None:
        for path in self.DOCKERFILES:
            with self.subTest(path=str(path)):
                text = path.read_text(encoding="utf-8")
                self.assertIn(self.PINNED_DIGEST, text)
                self.assertIn("1.90.0", text)
                self.assertRegex(text, r"release: 1\\.90\\.0")
                self.assertNotRegex(text, r"(?m)^FROM rust:")

    def test_release_prune_source_drops_strace_and_i2cget_only_when_release(self) -> None:
        prune = self.PRUNE.read_text(encoding="utf-8")
        posture = self.RELEASE_POSTURE.read_text(encoding="utf-8")
        fragment = self.COMMON_FRAGMENT.read_text(encoding="utf-8")
        self.assertIn("BR2_PACKAGE_STRACE=y", fragment)
        self.assertIn("# BR2_PACKAGE_I2C_TOOLS is not set", fragment)
        self.assertNotIn("BR2_PACKAGE_I2C_TOOLS=y", fragment)
        self.assertIn("DCENT_RELEASE_IMAGE", prune)
        self.assertIn("usr/bin/strace", prune)
        self.assertIn("usr/sbin/i2cget", prune)
        # WS-A4 re-anchor (2026-09-01): the truthy spelling table moved from
        # the prune script's inline `case` into the canonical resolver the
        # prune script now calls (dcent_release_posture_is_release). Pin the
        # spellings in their new single source and the call in the consumer;
        # the semantic (prune only on the RELEASE posture, DEV opts out) is
        # unchanged and additionally pinned functionally by
        # scripts/test_runtime_hardware_ownership.py.
        self.assertIn("dcent_release_posture_is_release", prune)
        self.assertIn("1|true|TRUE|yes|YES|y|Y", posture)
        self.assertIn("DCENT_DEV_IMAGE", posture)


if __name__ == "__main__":
    os.chdir(ROOT)
    unittest.main()
