#!/usr/bin/env python3
"""Pin the historical BM1396 ledger and explicit current native extension."""

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
    "bm1396_auto_adapt_voltage",
    "bm1396_carrier_preflight",
    "bm1396_contract",
    "bm1396_domain_voltage",
    "bm1396_fpga_abi",
    "bm1396_lifecycle",
    "bm1396_pic",
    "bm1396_submit_receiver",
    "bm1396_work",
    "bm1396_work_binding",
}
CURRENT_NATIVE_EXTENSIONS = {"bm1396_s17e_factory"}

EXPECTED_TESTS = {
    "Windows: py -3 -m pytest -q test_x17_amtc_evidence.py --rootdir=. from tools/ (12/12 held corpus)",
    "Linux: cargo +1.90.0 test -p dcentrald-common x17_amtc_recovery_evidence --lib (5/5)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1396_ (90/90)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --features recovery-tool --lib -- bm1396_ (91/91)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1396 --lib (4/4)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1396 --lib (5/5 data-only)",
    "python DCENT_OS_Antminer/scripts/test_bm1396_x17_ledger_convergence.py -q (6/6)",
}


class Bm1396X17LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1396"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1396 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1396_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1396_*.rs")}
        # The archived ten-module acceptance is not rewritten to claim tests
        # of the later S17e owner. Current source permits exactly that explicit
        # extension; current admission and native-owner tests qualify its use.
        self.assertEqual(source_modules, EXPECTED_MODULES | CURRENT_NATIVE_EXTENSIONS)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_every_contract_module_is_compile_exported_and_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in sorted(EXPECTED_MODULES | CURRENT_NATIVE_EXTENSIONS):
            self.assertIn(f"pub mod {module};", lib_rs)
        for module in sorted(EXPECTED_MODULES):
            self.assertIn(f"{module}.rs", anchor)
        self.assertIn("drivers/bm1396.rs", anchor)

    def test_row_records_current_depth_acceptance_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["acceptance_chip_labels"], ["BM1396"])
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 7)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 7)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "recovery-tool",
            "one-test feature delta",
            "send-before-track",
            "stock success weakness",
            "carrier None",
            "no ChipDriver implementation",
            "electrical-off",
        ):
            self.assertIn(needle, row)

    def test_live_driver_remains_absent_and_protocol_wrapper_non_authorizing(self) -> None:
        # Re-pinned 2026-09-12 (R06 wave-1 landing, V01-confirmed): the driver
        # now CARRIES an evidence-cited `impl ChipDriver for Bm1396Driver`
        # whose carrier-bound methods (init_chain/set_frequency/send_work/
        # set_voltage) REFUSE, naming the retained HAL owner
        # (`stock_bm1396::Transport`) and the 0x52 job-packet + DDR-DMA spine.
        # The load-bearing invariant is unchanged and stays pinned here:
        # `ChipRegistry::detect(0x1396)` remains None and the registry never
        # registers the driver (anti-BM1397-aliasing PR-056 pin below).
        helper = (ASIC_DRIVERS / "bm1396.rs").read_text(encoding="utf-8")
        registry = (ASIC_DRIVERS / "mod.rs").read_text(encoding="utf-8")
        for needle in (
            "impl ChipDriver for Bm1396Driver",
            "CARRIER_REFUSAL",
            "WORK_TX_REFUSAL",
            "stock_bm1396::Transport",
            "Promotion status: this `impl ChipDriver` is NOT regi",
        ):
            self.assertIn(needle, helper)
        self.assertNotIn("register(Box::new(bm1396::Bm1396Driver", registry)

    def test_workflow_runs_default_and_recovery_suites_with_zero_match_guards(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1396_",
            workflow,
        )
        self.assertIn(
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --features recovery-tool --lib -- bm1396_",
            workflow,
        )

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1396_x17_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
