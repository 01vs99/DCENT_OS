#!/usr/bin/env python3
"""Pin exact AML route-evidence modules, authority ceilings, and CI owners."""

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

ROW_MODULES = {
    "platform.t21_aml_production_route": "t21_aml_production_route",
    "platform.x19_aml_production_route": "x19_aml_production_route",
    "platform.s21xp_aml_evidence": "s21xp_aml_evidence",
}

CONVERGENCE_TEST = (
    "python DCENT_OS_Antminer/scripts/test_aml_route_evidence_ledger_convergence.py "
    "-q (6/6)"
)

ROW_TESTS = {
    "platform.t21_aml_production_route": {
        "Python: cd tools && python3 -m pytest -q test_t21_production_route_evidence.py --rootdir=. (17/17)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- t21_aml_production_route (5/5)",
        CONVERGENCE_TEST,
    },
    "platform.x19_aml_production_route": {
        "Python: cd tools && python3 -m pytest -q test_x19_aml_production_route_evidence.py --rootdir=. (21/21)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- x19_aml_production_route (5/5)",
        CONVERGENCE_TEST,
    },
    "platform.s21xp_aml_evidence": {
        "Python: cd tools && python3 -m pytest -q test_s21xp_air_topology_evidence.py test_s21xp_production_route_evidence.py --rootdir=. (32/32)",
        "Linux: bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s21xp_aml_evidence (5/5)",
        CONVERGENCE_TEST,
    },
}


class AmlRouteEvidenceLedgerConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.entries = {entry["id"]: entry for entry in ledger["entries"]}

    def test_each_platform_row_owns_only_its_exact_route_module(self) -> None:
        lib_rs = (COMMON_SRC / "lib.rs").read_text(encoding="utf-8")
        for row_id, module in ROW_MODULES.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["offline_contract_modules"], [module])
                self.assertTrue((COMMON_SRC / f"{module}.rs").is_file())
                self.assertIn(f"pub mod {module};", lib_rs)
                self.assertIn(f"{module}.rs", entry["dcentos_anchor"])

    def test_rows_record_measured_depth_and_non_authorizing_state(self) -> None:
        needles = {
            "platform.t21_aml_production_route": (
                "Awesome 1.2.6",
                "GPIO437",
                "PackageOnlyDenied",
                "management-only",
            ),
            "platform.x19_aml_production_route": (
                "S19 XP",
                "S19j XP",
                "PIC-versus-NoPic",
                "PackageOnlyDenied",
            ),
            "platform.s21xp_aml_evidence": (
                "ttyS4",
                "PIC1704",
                "NOT-IMPLEMENTED",
                "TD003",
            ),
        }
        for row_id, expected_tests in ROW_TESTS.items():
            with self.subTest(row=row_id):
                entry = self.entries[row_id]
                self.assertEqual(entry["status"], "evidence-insufficient")
                self.assertEqual(set(entry["tests"]), expected_tests)
                self.assertGreaterEqual(len(entry["safety"]), 4)
                self.assertGreaterEqual(len(entry["instrumentation"]), 4)
                row = json.dumps(entry, sort_keys=True)
                for needle in needles[row_id]:
                    self.assertIn(needle, row)

    def test_every_route_contract_keeps_all_action_authority_false(self) -> None:
        expectations = {
            "t21_aml_production_route": (
                "T21AmlProductionRouteAuthority::EvidenceOnly",
                "T21_AML_UNRESOLVED: [&str; 6]",
            ),
            "x19_aml_production_route": (
                "X19AmlProductionRouteAuthority::EvidenceOnly",
                "X19_AML_UNRESOLVED: [&str; 6]",
            ),
            "s21xp_aml_evidence": (
                "S21XpEvidenceAuthority::EvidenceOnly",
                "S21XP_UNRESOLVED: [&str; 7]",
            ),
        }
        for module, required in expectations.items():
            with self.subTest(module=module):
                source = (COMMON_SRC / f"{module}.rs").read_text(encoding="utf-8")
                for needle in required:
                    self.assertIn(needle, source)
                self.assertIn('["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]', source)
                permit_bodies = source.split("impl ", 1)[1].split("#[cfg(test)]", 1)[0]
                self.assertGreaterEqual(permit_bodies.count("pub const fn permits_"), 5)
                self.assertGreaterEqual(permit_bodies.count("false\n    }"), 5)

    def test_model_specific_asic_and_management_only_compositions_stay_distinct(self) -> None:
        # 2026-09-12 drift-13 adjudication: the XP pair and S21 XP rows landed
        # their exact typed native serial lanes (SerialWork over
        # AmlogicNativeSerial, generic construction Refused), so the old
        # ManagementOnly markers are gone from those two modules. T21 keeps
        # its ManagementOnly posture. Distinctness law unchanged: each module
        # pins its own protocol + engine + lifecycle, and every install
        # posture stays Denied.
        expected = {
            "t21_aml_production_route": (
                "AsicProtocolIdentity::Bm1368",
                "WorkEngineKind::ManagementOnly",
                "RuntimeStatus::ManagementOnlyByPolicy",
            ),
            "x19_aml_production_route": (
                "AsicProtocolIdentity::Bm1366",
                "WorkEngineKind::SerialWork",
                "LifecycleLane::AmlogicNativeSerial",
            ),
            "s21xp_aml_evidence": (
                "AsicProtocolIdentity::Bm1370",
                "WorkEngineKind::SerialWork",
                "LifecycleLane::AmlogicNativeSerial",
            ),
        }
        for module, needles in expected.items():
            with self.subTest(module=module):
                source = (COMMON_SRC / f"{module}.rs").read_text(encoding="utf-8")
                for needle in needles:
                    self.assertIn(needle, source)
        for module in ("x19_aml_production_route", "s21xp_aml_evidence"):
            source = (COMMON_SRC / f"{module}.rs").read_text(encoding="utf-8")
            self.assertIn("InstallAuthorization::Denied", source)
            self.assertIn("GenericConstruction::Refused", source)
        self.assertIn(
            "ArtifactInstallContract::PackageOnlyDenied",
            (COMMON_SRC / "t21_aml_production_route.rs").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "ArtifactInstallContract::PackageOnlyDenied",
            (COMMON_SRC / "x19_aml_production_route.rs").read_text(encoding="utf-8"),
        )
        s21xp = (COMMON_SRC / "s21xp_aml_evidence.rs").read_text(encoding="utf-8")
        self.assertIn("InstallAuthorization::Denied", s21xp)

    def test_workflow_runs_all_six_exact_python_and_rust_owners(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        for command in (
            "cd tools && python3 -m pytest -q test_t21_production_route_evidence.py --rootdir=.",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- t21_aml_production_route",
            "cd tools && python3 -m pytest -q test_x19_aml_production_route_evidence.py --rootdir=.",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- x19_aml_production_route",
            "cd tools && python3 -m pytest -q test_s21xp_air_topology_evidence.py test_s21xp_production_route_evidence.py --rootdir=.",
            "bash ../scripts/run_filtered_cargo_test.sh -p dcentrald-common --lib -- s21xp_aml_evidence",
        ):
            self.assertIn(command, workflow)

    def test_aggregate_gate_executes_this_convergence_suite(self) -> None:
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_aml_route_evidence_ledger_convergence.py -q", aggregate
        )


if __name__ == "__main__":
    unittest.main()
