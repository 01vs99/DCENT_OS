#!/usr/bin/env python3
"""Pin the complete autotuner module/profile inventory and offline suite owner."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
AUTOTUNER_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-autotuner"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_autotuner_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_COUNTS = {
    "aging_tracker": 10,
    "bad_chip_actuation": 12,
    "bad_chip_supervisor": 21,
    "binary_search": 20,
    "chain_voltage": 4,
    "chip_geometry": 0,
    "chip_health": 14,
    "chip_stats": 11,
    "config": 52,
    "dps": 4,
    "dps_governor": 26,
    "dvfs": 5,
    "efficiency": 15,
    "error_model": 7,
    "event_log": 0,
    "fleet": 15,
    "mcr_fit": 3,
    "power_budget": 37,
    "power_pid": 31,
    "profile": 12,
    "profitability": 18,
    "pvt_envelope": 33,
    "schedule": 6,
    "silicon_profile_select": 6,
    "silicon_report": 19,
    "state_persistence": 3,
    "telemetry": 9,
    "thermal_comp": 19,
    "tune_guard": 16,
    "tuner": 55,
    "tuner_stability": 8,
    "vnish_phase_fsm": 14,
    "voltage_domain": 5,
    "voltage_search": 17,
}

EXPECTED_TEST_HELPERS = {
    "apply_target_mode_for_test",
    "force_state_for_test",
    "install_profile_for_test",
    "last_applied_silicon_target_for_test",
    "last_resolved_power_target_watts_for_test",
    "runtime_status_for_test",
    "set_chain_hardware_identity_for_test",
    "set_night_hour_override_for_test",
    "set_target_mode_for_test",
    "tick_runtime_commands_for_test",
    "tick_silicon_profile_targets_for_test",
}


class DcentraldAutotunerModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}
        cls.lib_rs = (AUTOTUNER_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")

    def test_registry_exactly_matches_declared_public_and_private_modules(self) -> None:
        public = set(
            re.findall(r"^pub mod ([A-Za-z0-9_]+)[ \t]*(?:;|\{)", self.lib_rs, re.M)
        )
        private = set(re.findall(r"^mod ([A-Za-z0-9_]+)[ \t]*;", self.lib_rs, re.M))
        self.assertEqual(public, set(EXPECTED_COUNTS))
        self.assertEqual(set(self.modules), public)
        self.assertEqual(private, {"durable_json"})
        self.assertEqual(
            [row["module"] for row in self.registry["private_modules"]],
            ["durable_json"],
        )

    def test_every_source_scope_profile_and_ceiling_is_explicit(self) -> None:
        rows = [*self.registry["modules"], *self.registry["private_modules"]]
        for row in rows:
            with self.subTest(module=row["module"]):
                self.assertTrue((REPO_ROOT / row["source"]).is_file())
                self.assertEqual(row["compile_profiles"], ["default", "test_helpers"])
                self.assertTrue(row["ledger_rows"])
                self.assertGreaterEqual(len(row["authority_ceiling"]), 100)
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
        self.assertEqual(sum(EXPECTED_COUNTS.values()), 527)
        self.assertEqual(
            self.registry["private_modules"][0]["tests"],
            2,
        )
        self.assertEqual(
            self.registry["crate_root_test_prefixes"],
            [{"prefix": "tests", "tests": 6}],
        )
        self.assertEqual(self.registry["module_scoped_tests"], 527)
        self.assertEqual(self.registry["private_module_tests"], 2)
        self.assertEqual(self.registry["crate_root_tests"], 6)
        self.assertEqual(self.registry["total_tests"], 535)

    def test_feature_profile_is_exact_and_remains_test_only(self) -> None:
        tuner = (AUTOTUNER_ROOT / "src" / "tuner.rs").read_text(encoding="utf-8")
        helpers = set(
            re.findall(
                r'#\[cfg\(any\(test, feature = "test-helpers"\)\)\]\s+'
                r"pub(?: async)? fn ([A-Za-z0-9_]+)",
                tuner,
            )
        )
        self.assertEqual(helpers, EXPECTED_TEST_HELPERS)
        self.assertEqual(
            self.registry["feature_profiles"],
            [
                {
                    "profile": "default",
                    "features": [],
                    "public_modules": 34,
                    "extra_public_test_helper_methods": [],
                    "tests": 535,
                },
                {
                    "profile": "test_helpers",
                    "features": ["test-helpers"],
                    "public_modules": 34,
                    "extra_public_test_helper_methods": sorted(EXPECTED_TEST_HELPERS),
                    "tests": 535,
                    "authority_ceiling": self.registry["feature_profiles"][1][
                        "authority_ceiling"
                    ],
                },
            ],
        )
        cargo = (AUTOTUNER_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn("test-helpers = []", cargo)
        self.assertNotIn("dcentrald-hal", cargo)
        api_cargo = (
            DCENTOS_ROOT / "dcentrald" / "dcentrald-api" / "Cargo.toml"
        ).read_text(encoding="utf-8")
        dev_dependencies = api_cargo.split("[dev-dependencies]", 1)[1]
        self.assertIn(
            'dcentrald-autotuner = { path = "../dcentrald-autotuner", features = ["test-helpers"] }',
            dev_dependencies,
        )

    def test_high_risk_source_boundaries_remain_fail_closed(self) -> None:
        sources = {
            name: (AUTOTUNER_ROOT / "src" / f"{name}.rs").read_text(encoding="utf-8")
            for name in (
                "bad_chip_actuation",
                "bad_chip_supervisor",
                "binary_search",
                "config",
                "dps_governor",
                "durable_json",
                "power_budget",
                "pvt_envelope",
                "vnish_phase_fsm",
                "voltage_search",
            )
        }
        anchors = {
            "bad_chip_actuation": (
                "board_reset_is_refused_without_safeoff_receipt",
                "actuation_stays_disarmed_unless_both_flags",
            ),
            "bad_chip_supervisor": (
                "bad_chip_supervisor_defaults_on_without_granting_actuation",
                "supervisor_never_emits_fan_control_action",
            ),
            "binary_search": ("try_new_for_chip_refuses_unknown_pll",),
            "config": (
                "am2_frequency_autotune_defaults_off",
                "perf006_voltage_autotune_defaults_off",
            ),
            "dps_governor": ("scale_up_each_condition_failure_blocks_gate",),
            "durable_json": ("refuses_symlink_target_without_mutating_referent",),
            "power_budget": (
                "allocate_budget_fails_closed_on_zero_or_nonfinite_voltage",
            ),
            "pvt_envelope": (
                "w24_eff1_axis_aware_gate_defaults_off",
                "validate_freq_volt_bhb42803_voltage_fixed_only_accepts_1530",
            ),
            "vnish_phase_fsm": ("adapter_disabled_by_default_emits_noop",),
            "voltage_search": ("bm1398_no_voltage_search_when_voltage_fixed",),
        }
        for source, needles in anchors.items():
            for needle in needles:
                with self.subTest(source=source, anchor=needle):
                    self.assertIn(needle, sources[source])

        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-autotuner")
        ceiling = self.registry["authority_ceiling"]
        for needle in (
            "do not authorize live tuning",
            "frequency or voltage mutation",
            "rail control",
            "accepted shares",
            "hardware operation",
        ):
            self.assertIn(needle, ceiling)

    def test_workflow_aggregate_and_campaign_own_both_profiles(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "cargo test --locked -p dcentrald-autotuner --lib",
            "cargo test --locked -p dcentrald-autotuner --lib --features test-helpers",
        ):
            self.assertIn(command, workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_autotuner_module_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("autotuner-crate registry convergence", campaign)


if __name__ == "__main__":
    unittest.main()
