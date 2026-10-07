#!/usr/bin/env python3
"""Pin the BM1391/S15/T15 source, ledger, scaffold, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
ASIC_DRIVERS = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic" / "src" / "drivers"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {
    "bm1391_apw8_evidence",
    "bm1391_carrier_profile",
    "bm1391_safety_contract",
    "bm1391_share_qualification",
    "bm1391_stock_return",
    "bm1391_stock_startup",
    "bm1391_stock_work",
}

EXPECTED_TESTS = {
    "Windows: py -3 -m pytest -q test_s15_t15_apw8_evidence.py --rootdir=. from tools/ (21/21 held corpus)",
    "Windows: py -3 -m unittest DCENT_OS_Antminer/scripts/test_extract_s15_t15_bm1391_carrier.py (24 run; 23 passed, 1 symlink-creation skip)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1391_ (62/62)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1391 --lib (6/6)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1391 --lib (18/18 data-only)",
    "python DCENT_OS_Antminer/scripts/test_bm1391_s15_t15_ledger_convergence.py -q (6/6)",
}


class Bm1391S15T15LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1391"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1391 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1391_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1391_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_every_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)
        self.assertIn("drivers/bm1391.rs", anchor)

    def test_row_records_current_depth_acceptance_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["acceptance_chip_labels"], ["BM1391"])
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 8)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 8)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "production registry excludes",
            "explicit scaffold registry",
            "72-response",
            "60-chip",
            "pop-before-drop",
            "outer return one",
            "response-length placeholder",
            "electrical-off",
        ):
            self.assertIn(needle, row)

    def test_driver_and_registry_keep_every_live_path_scaffold_only(self) -> None:
        # Re-pinned 2026-09-12 (R04 wave-1 landing, V01-confirmed): the driver
        # is now release-scoped and evidence-backed — decode_nonce and the
        # stock-FPGA metadata are REAL (RESPONSE_BYTES_VERIFIED = true, 8-byte
        # record), while every CARRIER-BOUND operation (init_chain /
        # set_frequency / send_work) still REFUSES naming the owning artifacts
        # (stock_bm1391::Transport, dcentrald::bm1391_mining) and set_voltage
        # routes through the ownership SSOT that refuses before any I/O.
        # Registry invariant unchanged: production detect(0x1391) stays None.
        driver = (ASIC_DRIVERS / "bm1391.rs").read_text(encoding="utf-8")
        registry = (ASIC_DRIVERS / "mod.rs").read_text(encoding="utf-8")
        self.assertIn("impl ChipDriver for Bm1391Driver", driver)
        self.assertIn("DEFAULT_CHIPS_PER_CHAIN: Option<u8> = None", driver)
        self.assertIn("RESPONSE_BYTES_VERIFIED: bool = true", driver)
        for needle in (
            "CARRIER_REFUSAL",
            "FREQ_REFUSAL",
            "WORK_TX_REFUSAL",
            "stock_bm1391::Transport",
        ):
            self.assertIn(needle, driver)
        self.assertIn(
            "ChipRegistry::production().detect(bm1391::CHIP_ID).is_none()",
            registry,
        )
        self.assertIn("registry.detect(bm1391::CHIP_ID).is_some()", registry)

    def test_workflow_runs_common_suite_with_a_zero_match_guard(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1391_",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_bm1391_s15_t15_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
