#!/usr/bin/env python3
"""Pin the RE catalog modules, rows, vectors, consumers, and authority ceiling."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-re-catalog"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_re_catalog_surface_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

EXPECTED_MODULE_TESTS = {
    "fan_curves": set(),
    "model_catalog": {
        "bm1396_bm1397_model_mapping_is_not_reversed",
        "catalog_shape_strength_counts_and_provenance_are_pinned",
        "coverage_rows_are_unique_and_s23_stays_ground_truth_free",
        "exact_models_with_a_frequency_have_pll_facts",
        "voltage_bounds_are_ordered_when_present",
    },
    "pll_bible": {
        "bm1368_s21_representative_frequency_is_the_proven_525",
        "every_declared_reference_clock_is_25_mhz_today",
        "representative_freq_matches_a_catalogued_board",
        "representative_known_values_are_pinned",
        "rows_are_unique_and_scaffold_provenance_is_explicit",
    },
}
EXPECTED_MODELS = [
    ("s9", "0x1387", "Exact"),
    ("s9i", "0x1387", "Exact"),
    ("s9j", "0x1387", "Exact"),
    ("s9k", "0x1393", "Exact"),
    ("s11", "0x1391", "Structural"),
    ("s15", "0x1391", "Scaffold"),
    ("t15", "0x1391", "Scaffold"),
    ("s17", "0x1397", "Exact"),
    ("s17pro", "0x1397", "Exact"),
    ("t17", "0x1397", "Exact"),
    ("s17plus", "0x1397", "Structural"),
    ("t17plus", "0x1397", "Structural"),
    ("s17e", "0x1396", "Structural"),
    ("t17e", "0x1396", "Structural"),
    ("s19", "0x1398", "Structural"),
    ("s19pro", "0x1398", "Exact"),
    ("s19a", "0x1398", "Exact"),
    ("s19apro", "0x1398", "Exact"),
    # Gauntlet B5b (2026-09-02): stock topol NBS2003 = BM1360 (refutes 0x1398);
    # identity/geometry stock-exact but no held protocol detail -> Structural.
    ("s19i", "0x1360", "Structural"),
    # Gauntlet B5b (2026-09-02): corrected from Bitmain's own S19j-merge
    # stock topol (BHB42701 = BM1362, 108/chain; refutes the old 0x1398).
    ("s19j", "0x1362", "Exact"),
    ("s19jpro", "0x1362", "Exact"),
    ("s19jplus", "0x1362", "Exact"),
    ("s19xp", "0x1366", "Exact"),
    ("s19jxp", "0x1366", "Exact"),
    ("s19kpro", "0x1366", "Exact"),
    ("s21", "0x1368", "Exact"),
    ("s21pro", "0x1370", "Exact"),
    ("s21xp", "0x1370", "Exact"),
    ("s23", "0x1372", "Scaffold"),
]
EXPECTED_PLL_IDS = [
    "0x1387",
    "0x1391",
    "0x1397",
    "0x1398",
    "0x1362",
    "0x1366",
    "0x1368",
    "0x1370",
    "0x1372",
]
EXPECTED_REEXPORTS = [
    "model_evidence",
    "EvidenceStrength",
    "ModelEvidence",
    "ANTMINER_MODELS",
    "pll_expectation",
    "PllExpectation",
    "PLL_EXPECTATIONS",
]


def dependency_keys(manifest: str, section: str) -> set[str]:
    match = re.search(
        rf"^\[{re.escape(section)}\]\s*$\n(?P<body>.*?)(?=^\[|\Z)",
        manifest,
        re.M | re.S,
    )
    if match is None:
        return set()
    return set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", match.group("body"), re.M))


class DcentraldReCatalogSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.modules = {row["module"]: row for row in cls.registry["modules"]}
        cls.lib_rs = (CRATE_ROOT / "src" / "lib.rs").read_text(encoding="utf-8")
        cls.model_rs = (CRATE_ROOT / "src" / "model_catalog.rs").read_text(
            encoding="utf-8"
        )
        cls.pll_rs = (CRATE_ROOT / "src" / "pll_bible.rs").read_text(encoding="utf-8")
        cls.cargo_text = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        cls.ledger = {entry["id"]: entry for entry in ledger["entries"]}

    def test_module_sources_root_reexports_and_test_counts_are_exact(self) -> None:
        public = set(re.findall(r"^pub mod ([A-Za-z0-9_]+)", self.lib_rs, re.M))
        self.assertEqual(public, set(EXPECTED_MODULE_TESTS))
        self.assertEqual(set(self.modules), public)
        self.assertEqual(self.registry["declared_public_modules"], 3)
        expected_sources = {
            "fan_curves": "DCENT_OS_Antminer/dcentrald/dcentrald-re-catalog/src/lib.rs",
            "model_catalog": "DCENT_OS_Antminer/dcentrald/dcentrald-re-catalog/src/model_catalog.rs",
            "pll_bible": "DCENT_OS_Antminer/dcentrald/dcentrald-re-catalog/src/pll_bible.rs",
        }
        for module, source in expected_sources.items():
            self.assertEqual(self.modules[module]["source"], source)
            self.assertTrue((REPO_ROOT / source).is_file())
            self.assertEqual(self.modules[module]["compile_profiles"], ["default"])

        for module, expected_tests in EXPECTED_MODULE_TESTS.items():
            source = {
                "fan_curves": "",
                "model_catalog": self.model_rs,
                "pll_bible": self.pll_rs,
            }[module]
            actual = set(re.findall(r"#\[test\]\s+fn ([A-Za-z0-9_]+)\(", source))
            self.assertEqual(actual, expected_tests)
            self.assertEqual(self.modules[module]["tests"], len(expected_tests))
        self.assertEqual(self.registry["module_scoped_tests"], 10)
        self.assertEqual(self.registry["total_tests"], 10)
        self.assertEqual(self.registry["root_reexports"], EXPECTED_REEXPORTS)
        for symbol in EXPECTED_REEXPORTS:
            self.assertRegex(self.lib_rs, rf"\b{symbol}\b")

    def test_model_and_pll_row_identities_and_strengths_are_exact(self) -> None:
        models = re.findall(
            r'^\s*model!\("([^"]+)",\s*(0x[0-9a-f]+),.*?,\s*'
            r"(Exact|Structural|Scaffold),\s*&\[",
            self.model_rs,
            re.M,
        )
        self.assertEqual(models, EXPECTED_MODELS)
        self.assertEqual(
            [
                (row["slug"], row["chip_id"], row["strength"])
                for row in self.modules["model_catalog"]["model_rows"]
            ],
            EXPECTED_MODELS,
        )
        self.assertEqual(
            Counter(strength for _, _, strength in models),
            # Gauntlet B5b: s19j moved Structural -> Exact and s19i Exact ->
            # Structural (both stock-topol corrections) — the moves cancel.
            {"Exact": 19, "Structural": 7, "Scaffold": 3},
        )
        pll_ids = re.findall(r"PllExpectation \{ chip_id: (0x[0-9a-f]+),", self.pll_rs)
        self.assertEqual(pll_ids, EXPECTED_PLL_IDS)
        self.assertEqual(self.modules["pll_bible"]["chip_ids"], EXPECTED_PLL_IDS)
        self.assertIn('provenance: "SCAFFOLD_NO_GROUND_TRUTH"', self.pll_rs)
        self.assertIn("S23 reservation", self.model_rs)

    def test_manifest_dependency_consumer_and_lock_state_is_truthful(self) -> None:
        self.assertEqual(dependency_keys(self.cargo_text, "dependencies"), {"serde"})
        self.assertEqual(dependency_keys(self.cargo_text, "dev-dependencies"), set())
        self.assertEqual(self.registry["direct_dependencies"], ["serde"])
        self.assertEqual(self.registry["dev_dependencies"], [])
        self.assertNotIn("STATUS (2026-05-29): STUB", self.cargo_text)
        self.assertIn("STATUS (2026-08-19): OFFLINE EVIDENCE CATALOG", self.cargo_text)
        self.assertNotIn("serde_json =", self.cargo_text)

        consumers = []
        for manifest in (DCENTOS_ROOT / "dcentrald").glob("*/Cargo.toml"):
            if manifest == CRATE_ROOT / "Cargo.toml":
                continue
            manifest_text = manifest.read_text(encoding="utf-8")
            if "dcentrald-re-catalog" in dependency_keys(
                manifest_text, "dev-dependencies"
            ):
                consumers.append((manifest.parent.name, "dev-dependency"))
            for section in ("dependencies", "build-dependencies"):
                self.assertNotIn(
                    "dcentrald-re-catalog", dependency_keys(manifest_text, section)
                )
        self.assertEqual(consumers, [("dcentrald-asic", "dev-dependency")])
        self.assertEqual(
            [(row["crate"], row["scope"]) for row in self.registry["direct_consumers"]],
            consumers,
        )
        lock = (DCENTOS_ROOT / "dcentrald" / "Cargo.lock").read_text(encoding="utf-8")
        package = lock.split('name = "dcentrald-re-catalog"', 1)[1].split(
            "[[package]]", 1
        )[0]
        self.assertIn('"serde",', package)
        self.assertNotIn('"serde_json",', package)

    def test_vector_artifact_inventory_is_byte_and_hash_exact(self) -> None:
        actual_paths = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in (CRATE_ROOT / "vectors").rglob("*")
            if path.is_file()
        )
        registry_paths = [row["path"] for row in self.registry["vector_artifacts"]]
        self.assertEqual(registry_paths, actual_paths)
        self.assertEqual(len(registry_paths), 13)
        for row in self.registry["vector_artifacts"]:
            with self.subTest(path=row["path"]):
                path = REPO_ROOT / row["path"]
                payload = path.read_bytes()
                self.assertEqual(len(payload), row["bytes"])
                self.assertEqual(hashlib.sha256(payload).hexdigest(), row["sha256"])
                self.assertTrue(row["ledger_rows"])
                for owner in row["ledger_rows"]:
                    self.assertIn(owner, self.ledger)
                    self.assertIn(
                        self.ledger[owner]["status"],
                        {"experimental", "evidence-insufficient"},
                    )

    def test_catalog_remains_hal_free_and_non_authorizing(self) -> None:
        all_source = "\n".join((self.lib_rs, self.model_rs, self.pll_rs))
        self.assertIn("#![forbid(unsafe_code)]", self.lib_rs)
        for forbidden in (
            "use std::fs",
            "use std::net",
            "use std::process",
            "Command::new",
            "tokio::",
            "unsafe {",
        ):
            self.assertNotIn(forbidden, all_source)
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-re-catalog")
        self.assertEqual(
            self.registry["compile_profiles"],
            [
                {
                    "profile": "default",
                    "features": [],
                    "public_modules": 3,
                    "root_reexports": 7,
                    "module_scoped_tests": 10,
                    "total_tests": 10,
                }
            ],
        )
        for row in self.registry["modules"]:
            self.assertTrue(row["ledger_rows"])
            self.assertGreaterEqual(len(row["authority_ceiling"]), 110)
            for owner in row["ledger_rows"]:
                self.assertIn(owner, self.ledger)
                self.assertIn(
                    self.ledger[owner]["status"],
                    {"experimental", "evidence-insufficient"},
                )
        for needle in (
            "do not prove a deployed unit",
            "active carrier",
            "safe voltage or frequency",
            "accepted work",
            "hardware authority",
        ):
            self.assertIn(needle, self.registry["authority_ceiling"])

    def test_workflow_aggregate_campaign_and_vector_consumer_are_owned(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-re-catalog --lib", workflow)
        self.assertIn(
            "cargo test -p dcentrald-asic --features sim-hal --test golden_init_trace",
            workflow,
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_re_catalog_surface_registry.py -q", aggregate
        )
        self.assertIn(
            "cargo test -p dcentrald-asic --features sim-hal --test golden_init_trace",
            aggregate,
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("RE-catalog surface convergence", campaign)


if __name__ == "__main__":
    unittest.main()
