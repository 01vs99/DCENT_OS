#!/usr/bin/env python3
"""Pin the S9 SE offline-contract ledger to the executable source surface.

This test is deliberately host-pure. It reads source and campaign metadata; it
does not open a transport, contact a miner, or authorize any hardware action.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "s9se_boot",
    "s9se_cooling",
    "s9se_eeprom",
    "s9se_enum",
    "s9se_fpga",
    "s9se_gauntlet",
    "s9se_identity",
    "s9se_init",
    "s9se_job",
    "s9se_nand",
    "s9se_nonce",
    "s9se_pic",
    "s9se_pll",
    "s9se_regs",
    "s9se_temp",
    "s9se_timeout",
    "s9se_vil",
    "s9se_voltage",
    "s9se_work",
}


class S9SeLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1393"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1393 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_s9se_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("s9se_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(
            set(self.entry["offline_contract_modules"]),
            EXPECTED_MODULES,
            "the BM1393 ledger must converge when an s9se_* contract is added or removed",
        )

    def test_every_contract_module_is_compile_exported(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"pub mod {module};", lib_rs)

    def test_row_records_depth_without_promoting_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["board_targets"], ["am1-s9se"])
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "102/102",
            "reference-only",
            "NOT-IMPLEMENTED",
            "no chain transport",
            "no runtime",
            "live GetAddress response-body",
            "acknowledgement",
            "authenticated accepted-share",
            "NAND slot",
        ):
            self.assertIn(needle, row)
        self.assertNotIn("validated 256-MiB DMA base", row)
        self.assertNotIn("proven 256-MiB DMA base", row)

    def test_board_desc_keeps_only_the_current_capture_first_gaps(self) -> None:
        board_desc = (COMMON_SRC / "board_desc.rs").read_text(encoding="utf-8")
        block = board_desc.split("const AM1_S9SE_UNCONFIRMED_DATUMS", 1)[1].split(
            "];", 1
        )[0]
        self.assertIn("live GetAddress response body", block)
        self.assertIn("dsPIC33EP16GS202 IIC adapter ABI", block)
        self.assertIn("NAND slot layout", block)
        self.assertNotIn("DMA physical base", block)
        constructor = board_desc.split("pub const fn am1_s9se()", 1)[1].split(
            "pub const fn am1_s9k()", 1
        )[0]
        # Native C43 composition and generated SD media are now present. Keep
        # generic construction, automatic mining and onboard installation gated.
        for boundary in (
            "lane: LifecycleLane::C43Bm1393Native",
            "generic_construction: GenericConstruction::Refused",
            "chain_transport: ChainTransportKind::StockFpga",
            "work_engine: WorkEngineKind::FpgaWorkFifo",
            "asic_protocol: AsicProtocolIdentity::Bm1393",
            "slot_policy: SlotPolicy::LabGated",
            "release_channel: ReleaseChannel::Beta",
            "first_install_supported: false",
            "mining_default_enabled: false",
            "enablement: C43_NATIVE_MEDIA_ENABLEMENT",
        ):
            self.assertIn(boundary, constructor)
        media = board_desc.split("const C43_NATIVE_MEDIA_ENABLEMENT", 1)[1].split(
            "};", 1
        )[0]
        for boundary in (
            "external_media_mode: ExternalMediaMode::BootOnly",
            "external_media_maturity: ExternalMediaMaturity::ArtifactGenerated",
            "external_media_authorization: InstallAuthorization::LabOnly",
            "..ZYNQ_PACKAGE_ONLY_ENABLEMENT",
        ):
            self.assertIn(boundary, media)
        base = board_desc.split("const ZYNQ_PACKAGE_ONLY_ENABLEMENT", 1)[1].split(
            "};", 1
        )[0]
        for boundary in (
            "install_authorization: InstallAuthorization::Denied",
            "recovery_maturity: RecoveryMaturity::NotImplemented",
            "artifact_kind: ArtifactKind::SysupgradeBundle",
            "artifact_maturity: ArtifactMaturity::Experimental",
        ):
            self.assertIn(boundary, base)

    def test_ci_runs_the_zero_match_safe_s9se_suite(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s9se_",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
