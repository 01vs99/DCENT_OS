#!/usr/bin/env python3
"""Pin the complete path-aware dcentrald-hal module registry and CI owner."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
HAL_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-hal"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_hal_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_DEFAULT_COUNTS = {
    "adc": 4,
    "board_control": 12,
    "chain_backend": 0,
    "epic_umc_psu_v1": 7,
    "fan": 17,
    "fpga_chain": 18,
    "fpga_chain_backend": 12,
    "fpga_uart_relay": 7,
    "glitch_monitor": 8,
    "gpio": 1,
    "gpio_name_resolver": 0,
    "i2c": 79,
    "ina226": 3,
    "led": 2,
    "led_patterns": 0,
    "libgpiod": 2,
    "platform": 279,
    "pl_surface": 7,
    "pmbus": 32,
    "psu": 33,
    "psu_apw12_plus": 18,
    "psu_apw12_smbus": 28,
    "psu_apw9": 4,
    "psu_apw_uart_tunnel": 17,
    "psu_bypass_gate": 1,
    "psu_gpio_gate": 9,
    "psu_gpio_i2c": 12,
    "psu_routing": 1,
    "serial": 27,
    "serial_chain": 28,
    "stock_bc_execute": 13,
    "stock_fpga": 3,
    "stock_fpga_axi_mmap": 10,
    "stock_fpga_iic": 0,
    "stock_fpga_preflight": 2,
    "stock_fpga_work": 4,
    "transport_op_execute": 7,
    "uio": 2,
    "uio_discover": 3,
    "watchdog": 3,
    "xadc": 2,
}
EXPECTED_FEATURE_ONLY = {"stock_fpga_axi_ioctl": 6}
# The 717/723 harness counts below remain the historical observation. These
# newly registered public helpers add a separate lexical source inventory;
# neither arithmetic nor a query plan establishes a current full-suite result.
ADDITIVE_PUBLIC_SOURCE_TEST_ATTRIBUTES = {
    "bb_pic_application": 0,
    "bb_pic_heartbeat": 3,
    "bb_pic_rail": 4,
    "bb_management_runtime": 0,
}


class DcentraldHalModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.historical_modules = {row["module"]: row for row in cls.registry["modules"]}
        cls.additive_modules = {
            row["module"]: row for row in cls.registry["additive_public_source_modules"]
        }
        cls.modules = {**cls.historical_modules, **cls.additive_modules}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_registry_exactly_matches_declared_exports_and_compile_profiles(
        self,
    ) -> None:
        lib_rs = (HAL_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        declared = set(re.findall(r"^pub mod ([A-Za-z0-9_]+);", lib_rs, re.M))
        expected = (set(EXPECTED_DEFAULT_COUNTS) | set(EXPECTED_FEATURE_ONLY)
                    | set(ADDITIVE_PUBLIC_SOURCE_TEST_ATTRIBUTES))
        self.assertEqual(declared, expected)
        self.assertEqual(set(self.modules), declared)
        self.assertEqual(
            {name for name, row in self.modules.items() if row["default_enabled"]},
            set(EXPECTED_DEFAULT_COUNTS) | set(ADDITIVE_PUBLIC_SOURCE_TEST_ATTRIBUTES),
        )
        self.assertTrue(set(self.historical_modules).isdisjoint(self.additive_modules))
        self.assertEqual(set(self.additive_modules), set(ADDITIVE_PUBLIC_SOURCE_TEST_ATTRIBUTES))
        self.assertEqual(self.registry["current_declared_public_modules"], len(declared))
        self.assertEqual(self.registry["current_default_enabled_modules"], 45)
        for name, expected_tests in ADDITIVE_PUBLIC_SOURCE_TEST_ATTRIBUTES.items():
            row = self.additive_modules[name]
            text = (REPO_ROOT / row["source"]).read_text(encoding="utf-8")
            self.assertEqual(len(re.findall(r"^\s*#\[test\]\s*$", text, re.M)), expected_tests)
            self.assertEqual(row["lexical_test_attributes"], expected_tests)
            self.assertIsNone(row["new_full_suite_execution"])
        self.assertIn("historical", self.registry["test_count_scope"])
        self.assertIn("not a new full-suite", self.registry["test_count_scope"])
        self.assertRegex(
            lib_rs,
            r'#\[cfg\(feature = "axi-ioctl-debug"\)\]\s+pub mod stock_fpga_axi_ioctl;',
        )

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

    def test_default_zero_and_debug_feature_test_accounting_is_exact(self) -> None:
        default_observed = {
            name: row["default_tests"]
            for name, row in self.historical_modules.items()
            if row["default_enabled"]
        }
        self.assertEqual(default_observed, EXPECTED_DEFAULT_COUNTS)
        self.assertEqual(sum(EXPECTED_DEFAULT_COUNTS.values()), 717)
        zero_prefixes = sorted(
            name for name, tests in EXPECTED_DEFAULT_COUNTS.items() if tests == 0
        )
        self.assertEqual(self.registry["default_zero_test_prefixes"], zero_prefixes)
        self.assertEqual(
            sum(tests > 0 for tests in EXPECTED_DEFAULT_COUNTS.values()), 37
        )
        ioctl = self.modules["stock_fpga_axi_ioctl"]
        self.assertEqual(ioctl["required_feature"], "axi-ioctl-debug")
        self.assertEqual(ioctl["default_tests"], 0)
        self.assertEqual(ioctl["feature_tests"], 6)
        self.assertEqual(self.registry["default_tests"], 717)
        self.assertEqual(self.registry["axi_ioctl_debug_listed_tests"], 723)
        self.assertEqual(
            self.registry["axi_ioctl_debug_full_profile_expected_failures"], 3
        )
        self.assertEqual(self.registry["axi_ioctl_debug_focused_tests"], 6)
        self.assertEqual(self.registry["declared_public_modules"], 42)
        self.assertEqual(self.registry["default_enabled_modules"], 41)

    def test_source_retains_high_risk_non_authority_boundaries(self) -> None:
        sources = {
            "lib": (HAL_ROOT / "src" / "lib.rs").read_text(encoding="utf-8"),
            "fpga": (HAL_ROOT / "src" / "fpga_chain.rs").read_text(encoding="utf-8"),
            "glitch": (HAL_ROOT / "src" / "glitch_monitor.rs").read_text(
                encoding="utf-8"
            ),
            "pmbus": (HAL_ROOT / "src" / "pmbus.rs").read_text(encoding="utf-8"),
            "ioctl": (HAL_ROOT / "src" / "stock_fpga_axi_ioctl.rs").read_text(
                encoding="utf-8"
            ),
            "preflight": (HAL_ROOT / "src" / "stock_fpga_preflight.rs").read_text(
                encoding="utf-8"
            ),
            "pl_surface": (HAL_ROOT / "src" / "pl_surface.rs").read_text(
                encoding="utf-8"
            ),
            "psu_apw9": (HAL_ROOT / "src" / "psu_apw9.rs").read_text(
                encoding="utf-8"
            ),
            "psu_routing": (HAL_ROOT / "src" / "psu_routing.rs").read_text(
                encoding="utf-8"
            ),
            "amlogic": (HAL_ROOT / "src" / "platform" / "amlogic" / "mod.rs").read_text(
                encoding="utf-8"
            ),
        }
        self.assertIn("sim-hal is host-only", sources["lib"])
        for target in (
            "am1-s11",
            "am1-s9i",
            "am1-s9j",
            "am1-s9se",
            "am1-t9plus",
            "am2-s17e",
            "am2-t17e",
        ):
            self.assertIn(f'board_target: "{target}"', sources["fpga"])
        self.assertIn(
            "fabric_table_is_bijective_with_registered_zynq_targets", sources["fpga"]
        )
        self.assertIn("never gate any control", sources["glitch"])
        self.assertIn("Generic **read-only** PMBus telemetry", sources["pmbus"])
        self.assertIn("DEV/DEBUG ONLY", sources["ioctl"])
        self.assertIn("No issuer exists today", sources["preflight"])
        self.assertIn("A mismatch must refuse CTRL/BAUD/FIFO", sources["pl_surface"])
        self.assertIn("LIVE_DISPATCH_AVAILABLE: bool = false", sources["psu_apw9"])
        self.assertIn("SET voltage is refused. No opcode, no LSB, no I/O", sources["psu_routing"])
        self.assertIn('parse_psu_gpio_engaged("0\\n", recipe)', sources["amlogic"])
        self.assertIn('parse_psu_gpio_engaged("1\\n", recipe)', sources["amlogic"])
        self.assertIn('fn parse_psu_gpio_engaged(value: &str, recipe: Gpio437DriveRecipe)', sources["amlogic"])
        self.assertIn('psu_polarity_is_bound_to_the_exact_admitted_profile', sources["amlogic"])

    def test_registry_keeps_host_coverage_separate_from_hardware_authority(
        self,
    ) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-hal")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not authorize",
            "device open",
            "register access",
            "rail mutation",
            "physical hardware operation",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_and_aggregate_own_default_and_debug_profiles(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-hal --lib", workflow)
        self.assertIn(
            "run_filtered_cargo_test.sh -p dcentrald-hal --lib --features axi-ioctl-debug -- stock_fpga_axi_ioctl::tests",
            workflow,
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_dcentrald_hal_module_registry.py -q", aggregate)
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("HAL-crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
