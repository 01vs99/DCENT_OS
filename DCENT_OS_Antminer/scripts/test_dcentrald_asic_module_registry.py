#!/usr/bin/env python3
"""Pin the complete path-aware dcentrald-asic module registry and CI owner."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
ASIC_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-asic"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_asic_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_COUNTS = {
    "bm1362": 127,
    "bm1387": 12,
    "bm1393": 16,
    "chain": 18,
    "drivers": 181,
    "dspic": 156,
    "hw_err_tracker": 6,
    "pic": 12,
    "pic1704": 29,
    "protocol": 6,
    "register_transaction": 6,
    "serial_chip_address": 6,
    "uart_trans": 15,
    "voltage_rail_adapters": 3,
    "work_tx": 5,
}


class DcentraldAsicModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_registry_exactly_matches_compile_exported_top_level_modules(self) -> None:
        lib_rs = (ASIC_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        exported = set(re.findall(r"^pub mod ([A-Za-z0-9_]+);", lib_rs, re.M))
        self.assertEqual(exported, set(EXPECTED_COUNTS))
        self.assertEqual(set(self.modules), exported)

    def test_every_source_and_ledger_scope_exists_at_a_nonproduction_ceiling(
        self,
    ) -> None:
        for name, row in self.modules.items():
            with self.subTest(module=name):
                source = REPO_ROOT / row["source"]
                self.assertTrue(source.is_file(), source)
                self.assertTrue(row["ledger_rows"])
                self.assertGreaterEqual(len(row["authority_ceiling"]), 80)
                for owner in row["ledger_rows"]:
                    self.assertIn(owner, self.ledger)
                    self.assertIn(
                        self.ledger[owner]["status"],
                        {"experimental", "evidence-insufficient"},
                    )

    def test_test_accounting_is_exact_and_complete(self) -> None:
        self.assertEqual(
            {name: row["tests"] for name, row in self.modules.items()},
            EXPECTED_COUNTS,
        )
        self.assertEqual(sum(EXPECTED_COUNTS.values()), 598)
        self.assertEqual(
            self.registry["crate_root_test_prefixes"],
            [
                {"prefix": "mock_chain_mini_soak", "tests": 1},
                {"prefix": "process_environment_source_contract", "tests": 2},
            ],
        )
        self.assertEqual(self.registry["module_scoped_tests"], 598)
        self.assertEqual(self.registry["crate_root_tests"], 3)
        self.assertEqual(self.registry["total_tests"], 601)

    def test_source_retains_high_risk_non_authority_boundaries(self) -> None:
        sources = {
            "lib": (ASIC_ROOT / "src" / "lib.rs").read_text(encoding="utf-8"),
            "chain": (ASIC_ROOT / "src" / "chain.rs").read_text(encoding="utf-8"),
            "drivers": (ASIC_ROOT / "src" / "drivers" / "mod.rs").read_text(
                encoding="utf-8"
            ),
            "uart": (ASIC_ROOT / "src" / "uart_trans" / "mod.rs").read_text(
                encoding="utf-8"
            ),
            "voltage": (ASIC_ROOT / "src" / "voltage_rail_adapters.rs").read_text(
                encoding="utf-8"
            ),
            "work_tx": (ASIC_ROOT / "src" / "work_tx.rs").read_text(
                encoding="utf-8"
            ),
        }
        # "not in ChipRegistry" was the pre-2026-08-28 boundary; BM1393 gained
        # a registered scaffold that day, so the pinned truth moved to the
        # maturity boundary (registration exists but carries zero runtime
        # authority — every hardware method refuses at Scaffold maturity).
        for needle in ("reference only", "fail-closed Scaffold maturity, never production"):
            self.assertIn(needle, sources["lib"])
        for needle in (
            "serial_enumeration_is_typed_unverified_and_never_measured_eligible",
            "driver_for_chain_skips_divergent_production_chip_ids",
        ):
            self.assertIn(needle, sources["chain"])
        for needle in (
            "production_registry_excludes_scaffold_drivers",
            "scaffold_drivers_require_both_gates",
        ):
            self.assertIn(needle, sources["drivers"])
        self.assertIn(
            "open_paths_requires_four_ttys_before_touching_paths", sources["uart"]
        )
        self.assertIn(
            "external_dac_factory_is_unsupported_on_energize", sources["voltage"]
        )
        for needle in (
            "This module does **not** write FPGA FIFOs",
            "Unknown chip IDs error",
            "module_does_not_write_hardware",
        ):
            self.assertIn(needle, sources["work_tx"])

    def test_registry_keeps_crate_presence_separate_from_hardware_authority(
        self,
    ) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-asic")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not by themselves authorize",
            "carrier",
            "rail",
            "accepted share",
            "hardware operation",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_and_aggregate_own_registry_and_complete_crate_suite(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-asic --lib", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_dcentrald_asic_module_registry.py -q", aggregate)
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("ASIC-crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
