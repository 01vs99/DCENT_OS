#!/usr/bin/env python3
"""Pin the BM1398/S19/T19 source, ledger, refusal, and CI contract."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
COMMON_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-common" / "src"
API_TYPES_SRC = DCENTOS_ROOT / "dcentrald" / "dcentrald-api-types" / "src"
ASIC_DRIVERS = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic" / "src" / "drivers"
SERIAL_MINING = DCENTOS_ROOT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULES = {"bm1398_nbp1901_stub"}

EXPECTED_TESTS = {
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1398_ (11/11)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-api-types --lib -- bm1398_protocol (18/18)",
    "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- bm1398_ (16/16)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic drivers::bm1398 --lib (6/6)",
    "Linux: cargo +1.90.0 test -p dcentrald-asic chain::tests::bm1398 --lib (3/3)",
    "Linux: cargo +1.90.0 test -p dcentrald-silicon-profiles bm1398 --lib (30/30 data-only)",
    "python DCENT_OS_Antminer/scripts/test_bm1398_s19_t19_ledger_convergence.py -q (6/6)",
}


class Bm1398S19T19LedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        matches = [entry for entry in ledger["entries"] if entry["id"] == "asic.bm1398"]
        if len(matches) != 1:
            raise AssertionError(f"expected one asic.bm1398 entry, found {len(matches)}")
        cls.entry = matches[0]

    def test_ledger_tracks_every_bm1398_contract_module_exactly(self) -> None:
        source_modules = {path.stem for path in COMMON_SRC.glob("bm1398_*.rs")}
        self.assertEqual(source_modules, EXPECTED_MODULES)
        self.assertEqual(set(self.entry["offline_contract_modules"]), EXPECTED_MODULES)

    def test_contract_module_and_split_truth_surfaces_are_anchored(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        anchor = self.entry["dcentos_anchor"]
        for module in EXPECTED_MODULES:
            self.assertIn(f"pub mod {module};", lib_rs)
            self.assertIn(f"{module}.rs", anchor)
        for path in (
            "bm1398_protocol.rs",
            "drivers/bm1398.rs",
            "serial_mining.rs",
        ):
            self.assertIn(path, anchor)

    def test_row_records_current_depth_acceptance_and_no_authority(self) -> None:
        self.assertEqual(self.entry["status"], "evidence-insufficient")
        self.assertEqual(self.entry["acceptance_chip_labels"], ["BM1398"])
        self.assertEqual(set(self.entry["tests"]), EXPECTED_TESTS)
        self.assertGreaterEqual(len(self.entry["safety"]), 8)
        self.assertGreaterEqual(len(self.entry["instrumentation"]), 8)
        row = json.dumps(self.entry, sort_keys=True)
        for needle in (
            "missing held deployed S19 Pro EEPROM page",
            "production recognition returns no driver",
            "exact-chip experimental policy",
            "default-off open-core",
            "refusal before optional hardware observation",
            "wrong PIC16 voltage spine",
            "15.0 V fixture",
            "accepted-share",
        ):
            self.assertIn(needle, row)

    def test_readiness_driver_and_native_route_remain_fail_closed(self) -> None:
        stub = (COMMON_SRC / "bm1398_nbp1901_stub.rs").read_text(encoding="utf-8")
        api = (API_TYPES_SRC / "bm1398_protocol.rs").read_text(encoding="utf-8")
        driver = (ASIC_DRIVERS / "bm1398.rs").read_text(encoding="utf-8")
        registry = (ASIC_DRIVERS / "mod.rs").read_text(encoding="utf-8")
        serial = SERIAL_MINING.read_text(encoding="utf-8")
        for needle in (
            "BM1398_NBP1901_PROTOCOL_RECONSTRUCTED: bool = true",
            "BM1398_NBP1901_DEPLOYED_IDENTITY_HELD: bool = false",
            "BM1398_NBP1901_ADMIT: bool = false",
            "BM1398_MINING_DEFAULT_ENABLED: bool = false",
        ):
            self.assertIn(needle, stub)
        self.assertIn("S19_PRO_NBP1901_BM1398_PROFILE", api)
        self.assertIn("if !bm139x_open_core_enabled()", driver)
        self.assertIn("AsicProtocolIdentity::Bm1398", driver)
        self.assertIn("production.detect(bm1398::CHIP_ID).is_none()", registry)
        self.assertIn("ChipRegistry::with_experimental_driver(bm1398::CHIP_ID)", registry)
        self.assertIn("if is_bm1398 && !passthrough", serial)
        self.assertIn(
            "bm1398_native_route_consumes_exact_admission_before_generic_hardware",
            serial,
        )
        # The old generic protocol stub still refuses. The separate native
        # owner consumes exact admission before generic serial observation.
        production = serial.split("\n#[cfg(test)]\nmod tests {", 1)[0]
        run = production.split("pub async fn run(&mut self)", 1)[1]
        branch_start = run.index("if is_bm1398 && !passthrough {")
        dispatch = run.index("return crate::s19_bm1398_native_mining::run(", branch_start)
        generic = run.index("let nopic = if s19k_install_custody_safeoff")
        self.assertLess(dispatch, generic)
        admission = "".join(run[branch_start:dispatch].split())
        self.assertIn("runtime_dispatch_admission.take()", admission)
        # Re-pinned 2026-09-12 (R07 wave-1 landing, V01-confirmed): the handoff
        # admits the exact BM1398 FAMILY (am2-s19pro / am2-s19 / am2-t19) via
        # the platform profile table; per-bin geometry/ladders live in
        # s19_bm1398_platform and are pinned by the r07 suites. The identity
        # requirement is unchanged and stays pinned.
        self.assertIn(
            "crate::s19_bm1398_native_mining::platform::Bm1398Platform::from_admission("
            "admission.board_target(),admission.identity(),).is_ok()",
            admission,
        )
        self.assertIn("admission.identity()==dcentrald_common::AsicProtocolIdentity::Bm1398", admission)

    def test_workflow_runs_all_three_family_suites_with_zero_match_guards(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- bm1398_",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-api-types --lib -- bm1398_protocol",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald --bin dcentrald -- bm1398_",
        ):
            self.assertIn(command, workflow)

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_bm1398_s19_t19_ledger_convergence.py -q", aggregate)


if __name__ == "__main__":
    unittest.main()
