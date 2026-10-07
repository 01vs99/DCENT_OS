#!/usr/bin/env python3
"""Pin the path-aware silicon-profile module registry and both CI profiles."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
SILICON_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-silicon-profiles"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_silicon_profiles_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_DEFAULT_COUNTS = {
    "asics": 17,
    "bitmain_guide_thermal": 15,
    "bm1362": 79,
    "bm1366": 37,
    "bm1368": 28,
    "bm1370": 22,
    "bm1385": 2,
    "bm1387": 9,
    "bm1390": 14,
    "bm1391": 6,
    "bm1391_stock_fw": 9,
    "bm1396": 3,
    "bm1397": 11,
    "bm1398": 28,
    "bm1485": 10,
    "bm1489": 9,
    "efficiency": 11,
    "energize_gate": 26,
    "gdtuner": 13,
    "gpio_maps": 18,
    "hashboard_catalog": 15,
    "hashboard_topology": 18,
    "hashboards": 14,
    "hydro_fleet": 13,
    "operating_points": 17,
    "pic1704_crc": 4,
    "pic_heartbeat": 10,
    "pics": 13,
    "power_topology": 12,
    "psus": 13,
    "registry": 38,
    "s19k_nopic_admission": 14,
    # B5b/B6 stock transcription modules — registered retroactively by B9
    # 2026-09-02 (the merges declared them in lib.rs but this registry
    # lagged; pre-existing main drift cured).
    "s19_family_stock": 11,
    "s19_family_stock_topol": 9,
    "scrypt_stock_topology": 17,
    "sensor_topology": 14,
    "staggered_powerup": 12,
    # B9 T21 stock contracts module (2026-09-02).
    "t21_stock_topol": 11,
    # B10 S21 air family stock contracts + controller adjudication (2026-09-02).
    "s21_family_stock_topol": 12,
    "vnish_thermal": 11,
}
EXPECTED_FEATURE_ONLY = {"bm1360": 5, "bm1373": 5, "bm1491": 6}


class DcentraldSiliconProfilesModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_registry_exactly_matches_declared_exports_and_compile_profiles(
        self,
    ) -> None:
        lib_rs = (SILICON_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        declared = set(re.findall(r"^pub mod ([A-Za-z0-9_]+);", lib_rs, re.M))
        expected = set(EXPECTED_DEFAULT_COUNTS) | set(EXPECTED_FEATURE_ONLY)
        self.assertEqual(declared, expected)
        self.assertEqual(set(self.modules), declared)
        self.assertEqual(
            {name for name, row in self.modules.items() if row["default_enabled"]},
            set(EXPECTED_DEFAULT_COUNTS),
        )
        gated = set(
            re.findall(
                r'#\[cfg\(feature = "experimental_chips"\)\]\s+pub mod ([A-Za-z0-9_]+);',
                lib_rs,
            )
        )
        self.assertEqual(gated, set(EXPECTED_FEATURE_ONLY))

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

    def test_default_and_experimental_test_accounting_is_exact(self) -> None:
        default_observed = {
            name: row["default_tests"]
            for name, row in self.modules.items()
            if row["default_enabled"]
        }
        self.assertEqual(default_observed, EXPECTED_DEFAULT_COUNTS)
        self.assertEqual(sum(EXPECTED_DEFAULT_COUNTS.values()), 645)
        self.assertEqual(
            self.registry["crate_root_test_prefixes"],
            [{"prefix": "tests", "tests": 6}],
        )
        self.assertEqual(self.registry["default_module_tests"], 645)
        self.assertEqual(self.registry["default_tests"], 651)
        for name, count in EXPECTED_FEATURE_ONLY.items():
            row = self.modules[name]
            self.assertFalse(row["default_enabled"])
            self.assertEqual(row["required_feature"], "experimental_chips")
            self.assertEqual(row["default_tests"], 0)
            self.assertEqual(row["feature_tests"], count)
        self.assertEqual(sum(EXPECTED_FEATURE_ONLY.values()), 16)
        self.assertEqual(self.registry["experimental_chips_tests"], 667)
        self.assertEqual(self.registry["declared_public_modules"], 43)
        self.assertEqual(self.registry["default_enabled_modules"], 40)

    def test_source_retains_high_risk_non_authority_boundaries(self) -> None:
        sources = {
            "lib": (SILICON_ROOT / "src" / "lib.rs").read_text(encoding="utf-8"),
            "bm1360": (SILICON_ROOT / "src" / "bm1360.rs").read_text(encoding="utf-8"),
            "bm1373": (SILICON_ROOT / "src" / "bm1373.rs").read_text(encoding="utf-8"),
            "bm1491": (SILICON_ROOT / "src" / "bm1491.rs").read_text(encoding="utf-8"),
            "energize": (SILICON_ROOT / "src" / "energize_gate.rs").read_text(
                encoding="utf-8"
            ),
            "catalog": (SILICON_ROOT / "src" / "hashboard_catalog.rs").read_text(
                encoding="utf-8"
            ),
            "power": (SILICON_ROOT / "src" / "power_topology.rs").read_text(
                encoding="utf-8"
            ),
        }
        self.assertIn("#![forbid(unsafe_code)]", sources["lib"])
        for module in ("bm1360", "bm1373", "bm1491"):
            self.assertIn("ChipStatus::RegisterMappedFromRE", sources[module])
        self.assertIn("env_strict_refuse_default_on", sources["energize"])
        self.assertIn("env_accept_degraded_default_off", sources["energize"])
        self.assertIn("This table authorizes nothing", sources["catalog"])
        self.assertIn("Nothing in this crate can construct a driver", sources["power"])

    def test_registry_keeps_profile_data_separate_from_hardware_authority(
        self,
    ) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-silicon-profiles")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not authorize",
            "profile selection",
            "voltage mutation",
            "accepted shares",
            "physical hardware operation",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_and_aggregate_own_both_complete_profiles(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "cargo test --locked -p dcentrald-silicon-profiles --lib", workflow
        )
        self.assertIn(
            "cargo test --locked -p dcentrald-silicon-profiles --lib --features experimental_chips",
            workflow,
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_silicon_profiles_module_registry.py -q",
            aggregate,
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("silicon-profile crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
