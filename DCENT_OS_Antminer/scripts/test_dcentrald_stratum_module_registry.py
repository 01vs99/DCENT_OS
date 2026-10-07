#!/usr/bin/env python3
"""Pin the complete dcentrald-stratum module and authority surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-stratum"
SOURCE_ROOT = CRATE_ROOT / "src"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_stratum_module_registry.json"
)
LEDGER_PATH = (
    REPO_ROOT
    / "docs"
    / "dev"
    / "2026-08-05-hardware-supremacy-campaign"
    / "capability-ledger.json"
)

PUBLIC_PATTERNS = {
    "structs": r"^pub struct\s+",
    "enums": r"^pub enum\s+",
    "traits": r"^pub trait\s+",
    "type_aliases": r"^pub type\s+",
    "functions_and_methods": r"^\s*pub(?:\s+(?:async|const|unsafe))*\s+fn\s+",
    "constants": r"^pub const\s+",
    "statics": r"^pub static\s+",
}

TEST_PATTERN = re.compile(
    r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*"
    r"(?:#\[[^\]]+\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)

# module, source below src/, compile feature, surface class, all-feature tests
MODULE_SPECS = [
    ("acceptance_tracker", "acceptance_tracker.rs", None, "accounting_state", 9),
    ("coin", "coin.rs", "scrypt-l7", "algorithm_catalog", 5),
    ("derivations", "derivations.rs", None, "pure_derivation", 16),
    ("pool_api", "pool_api.rs", None, "dto_catalog", 28),
    ("pool_failover", "pool_failover.rs", None, "state_machine", 19),
    ("pool_quality", "pool_quality.rs", None, "telemetry_projection", 12),
    ("router", "router.rs", None, "runtime_router", 37),
    ("scrypt", "scrypt.rs", None, "algorithm_contract", 2),
    ("share_pipeline", "share_pipeline.rs", None, "work_validation", 2),
    ("types", "types.rs", None, "dto_catalog", 35),
    ("url_validator", "url_validator.rs", None, "parser_policy", 37),
    ("v1", "v1/mod.rs", None, "namespace", 0),
    ("v1.client", "v1/client.rs", None, "network_runtime", 142),
    ("v1.codec", "v1/codec.rs", None, "codec_parser", 18),
    ("v1.connection", "v1/connection.rs", None, "network_transport", 28),
    ("v1.difficulty", "v1/difficulty.rs", None, "pure_derivation", 23),
    ("v1.job", "v1/job.rs", None, "work_builder", 26),
    ("v1.messages", "v1/messages.rs", None, "codec_parser", 63),
    ("v1.policy", "v1/policy.rs", None, "parser_policy", 2),
    ("v1.mock_pool", "v1/mock_pool.rs", "mock-pool", "test_harness", 2),
    ("v2", "v2/mod.rs", None, "namespace", 0),
    ("v2.adapter", "v2/adapter.rs", "sv2", "work_adapter", 44),
    ("v2.auth", "v2/auth.rs", "sv2", "authentication_policy", 9),
    ("v2.channel", "v2/channel.rs", "sv2", "protocol_state_machine", 71),
    ("v2.client", "v2/client.rs", "sv2", "network_runtime", 30),
    (
        "v2.difficulty_autotune",
        "v2/difficulty_autotune.rs",
        "sv2",
        "pure_derivation",
        19,
    ),
    ("v2.framing", "v2/framing.rs", "sv2", "codec_parser", 22),
    ("v2.jd", "v2/jd.rs", "jd", "network_runtime", 26),
    ("v2.noise", "v2/noise.rs", "sv2", "cryptographic_transport", 49),
    ("v2.test_server", "v2/test_server.rs", "mock-pool", "test_harness", 0),
    ("v2.types", "v2/types.rs", "sv2", "dto_catalog", 17),
    ("version_mask", "version_mask.rs", None, "work_validation", 4),
    ("work", "work.rs", None, "work_validation", 34),
    ("work_domain", "work_domain.rs", None, "allocator_state", 5),
]

PROFILE_SPECS = [
    # One new work.rs regression is feature-independent. These remain source
    # expectations; this registry update does not claim a new Cargo execution.
    ("v1_only", [], 22, 542, 1, 1, 544),
    ("sv2_only", ["sv2"], 30, 802, 1, 1, 804),
    ("default", ["sv2", "jd"], 31, 829, 1, 1, 831),
    ("scrypt_l7", ["sv2", "jd", "scrypt-l7"], 32, 834, 1, 1, 837),
    ("mock_default", ["sv2", "jd", "mock-pool"], 33, 831, 10, 1, 842),
    (
        "all_features",
        ["sv2", "jd", "scrypt-l7", "mock-pool"],
        34,
        836,
        10,
        1,
        847,
    ),
]

INTEGRATION_SPECS = [
    ("sv2_multi_pool", "tests/sv2_multi_pool.rs", "mock-pool", 7),
    ("v1_mock_pool", "tests/v1_mock_pool.rs", "mock-pool", 2),
    ("v1_parser_corpus", "tests/v1_parser_corpus.rs", None, 1),
]

DIRECT_CONSUMERS = [
    "DCENT_OS_Antminer/dcentrald/dcentrald",
    "DCENT_OS_Antminer/dcentrald/dcentrald-api",
    "DCENT_OS_Antminer/dcentrald/fuzz",
    "DCENT_OS_WhatsMiner/dcentrald/dcentrald",
]

SURFACE_CLASSES = {
    "accounting_state": "In-memory accepted/rejected share accounting; no pool truth oracle.",
    "algorithm_catalog": "Feature-gated coin/algorithm vocabulary; no Scrypt implementation or miner route.",
    "pure_derivation": "Pure bounded arithmetic and formatting from caller-owned values.",
    "dto_catalog": "Protocol/config/status vocabulary; construction is not observation or admission.",
    "state_machine": "In-memory failover transitions; runtime drive remains separately gated.",
    "telemetry_projection": "Projection of locally observed protocol state; not pool-side ground truth.",
    "runtime_router": "Selects and launches configured clients; it grants no endpoint trust by itself.",
    "algorithm_contract": "Scrypt wire facts plus an explicit unimplemented share-check refusal.",
    "work_validation": "Host work construction/validation; accepted local hashes are not pool acceptance.",
    "parser_policy": "URL/parser admission policy; parsing does not authenticate DNS or the peer.",
    "namespace": "Public module namespace with feature-gated children.",
    "network_runtime": "Async TCP protocol runtime; network contact occurs only when a consumer runs it.",
    "codec_parser": "Bounded wire encoding/decoding over caller-owned bytes.",
    "network_transport": "V1 TCP/TLS transport with configured endpoint authority.",
    "work_builder": "Transforms jobs into host work; no ASIC dispatch or share-delivery proof.",
    "test_harness": "Feature-gated loopback-only mock server/client helpers; never production-default.",
    "work_adapter": "Maps SV2 channel/job state into shared work vocabulary.",
    "authentication_policy": "Authority-key and local-only exception policy; no key provisioning owner.",
    "protocol_state_machine": "SV2 channel transitions and bounded frame handling.",
    "cryptographic_transport": "Noise encryption and certificate verification; endpoint trust requires a pinned key.",
    "allocator_state": "Finite V1 extranonce/generation allocation in memory.",
}


def public_census(text: str) -> dict[str, int]:
    return {
        name: len(re.findall(pattern, text, re.MULTILINE))
        for name, pattern in PUBLIC_PATTERNS.items()
    }


def test_names(text: str) -> list[str]:
    return TEST_PATTERN.findall(text)


def manifest_section_keys(text: str, section: str) -> set[str]:
    keys: set[str] = set()
    active = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == f"[{section}]"
            continue
        if active and line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


def manifest_features(text: str) -> dict[str, list[str]]:
    features: dict[str, list[str]] = {}
    active = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == "[features]"
            continue
        if not active or not line or "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        features[name] = re.findall(r'"([^"]+)"', value)
    return features


def pub_use_statements(text: str) -> list[str]:
    statements: list[str] = []
    pending: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and line.startswith("pub use "):
            pending.append(line)
        elif pending:
            pending.append(line)
        if pending and line.endswith(";"):
            statements.append(" ".join(" ".join(pending).split()))
            pending = []
    if pending:
        raise AssertionError("unterminated pub use statement")
    return statements


def feature_active(required: str | None, enabled: set[str]) -> bool:
    return required is None or required in enabled


def build_registry() -> dict[str, object]:
    rows = []
    texts = [(SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")]
    for module, source, feature, surface_class, expected_tests in MODULE_SPECS:
        path = SOURCE_ROOT / source
        text = path.read_text(encoding="utf-8")
        texts.append(text)
        discovered_tests = len(test_names(text))
        if discovered_tests != expected_tests:
            raise AssertionError(
                f"{module} test census drifted: {discovered_tests} != {expected_tests}"
            )
        rows.append(
            {
                "module": module,
                "source": (
                    "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/src/" + source
                ),
                "compile_feature": feature,
                "surface_class": surface_class,
                "tests_all_features": discovered_tests,
                "public_definition_census": public_census(text),
                "ledger_rows": [],
            }
        )

    integration_rows = []
    for name, source, feature, expected_tests in INTEGRATION_SPECS:
        path = CRATE_ROOT / source
        discovered_tests = len(test_names(path.read_text(encoding="utf-8")))
        if discovered_tests != expected_tests:
            raise AssertionError(
                f"{name} integration census drifted: {discovered_tests} != {expected_tests}"
            )
        integration_rows.append(
            {
                "name": name,
                "source": "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/" + source,
                "compile_feature": feature,
                "tests": discovered_tests,
            }
        )

    profiles = []
    for (
        name,
        features,
        expected_modules,
        library_tests,
        integration_tests,
        doc_tests,
        package_tests,
    ) in PROFILE_SPECS:
        enabled = set(features)
        active_modules = sorted(
            row["module"]
            for row in rows
            if feature_active(row["compile_feature"], enabled)
        )
        if len(active_modules) != expected_modules:
            raise AssertionError(
                f"{name} module census drifted: {len(active_modules)} != {expected_modules}"
            )
        profiles.append(
            {
                "name": name,
                "features": features,
                "active_modules": active_modules,
                "library_tests": library_tests,
                "integration_tests": integration_tests,
                "doc_tests": doc_tests,
                "package_tests": package_tests,
                "benchmarks": 0,
            }
        )

    manifest = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    all_source = "\n".join(texts)
    return {
        "schema_version": 1,
        "generated": "2026-09-07",
        "crate": "dcentrald-stratum",
        "crate_root": "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/src/lib.rs",
        "authority_ceiling": (
            "Protocol clients, local work validation, encrypted transcripts, and "
            "loopback mock acceptance do not prove DNS/peer identity, pool custody, "
            "live accepted shares, payout correctness, miner hardware identity, ASIC "
            "dispatch, safe operating points, or any hardware actuator."
        ),
        "ledger_scope_reason": (
            "No current hardware-capability ledger row names dcentrald-stratum as an "
            "evidence anchor. Network protocol maturity cannot be laundered into "
            "silicon, carrier, power, thermal, work-delivery, or share-acceptance maturity."
        ),
        "source_policy": {
            "rust_source_files": len(list(SOURCE_ROOT.rglob("*.rs"))),
            "public_module_files": len(rows),
            "source_bytes": sum(path.stat().st_size for path in SOURCE_ROOT.rglob("*.rs")),
            "unsafe_blocks": len(re.findall(r"\bunsafe\s*\{", all_source)),
            "production_network_runtime": [
                "v1.client",
                "v1.connection",
                "v2.client",
                "v2.jd",
            ],
            "production_filesystem_or_subprocess": [],
            "test_only_external_subprocess": {
                "module": "v2.jd",
                "env_gate": "DCENT_SV2_JD_REGTEST_BITCOIND",
                "default": "in-process high-fidelity mock",
            },
        },
        "surface_classes": SURFACE_CLASSES,
        "modules": rows,
        "root_surface": {
            "public_modules": [
                row["module"] for row in rows if "." not in row["module"]
            ],
            "public_use_statements": pub_use_statements(texts[0]),
            "direct_public_definition_census": public_census(texts[0]),
            "direct_tests": len(test_names(texts[0])),
        },
        "public_definition_totals": public_census(all_source),
        "all_feature_library_tests": sum(row["tests_all_features"] for row in rows),
        "integration_tests": integration_rows,
        "profiles": profiles,
        "features": manifest_features(manifest),
        "direct_dependencies": sorted(manifest_section_keys(manifest, "dependencies")),
        "dev_dependencies": sorted(manifest_section_keys(manifest, "dev-dependencies")),
        "direct_consumers": DIRECT_CONSUMERS,
        "security_invariants": [
            "the crate forbids unsafe code",
            "remote SV2 mining and JD peers require an exact authority key",
            "TOFU and explicit cleartext are restricted to the connected socket's loopback peer",
            "present-but-invalid authority keys never downgrade",
            "SV2 mining transport always uses Noise; JD cleartext is a local test exception only",
            "mock-pool server helpers are absent from production-default builds",
            "real bitcoind regtest execution requires an explicit environment path",
            "the removed sv2-pure-rust feature cannot advertise an unimplemented k256 fallback",
        ],
        "known_external_blockers": [
            "live accepted SV2 shares and pool accounting remain BENCH_HOLD",
            "remote endpoint trust requires operator-provisioned authority-key URLs",
            "Job Declaration is an opt-in supervisor/probe path, not proven work injection",
            "OCEAN DATUM is not implemented",
            "the Scrypt share-check path explicitly refuses as unimplemented",
        ],
    }


class DcentraldStratumModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = build_registry()
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    def test_registry_is_exact_and_complete(self) -> None:
        self.assertEqual(self.registry, self.expected)
        self.assertEqual(len(self.registry["modules"]), 34)
        self.assertEqual(self.registry["source_policy"]["rust_source_files"], 35)
        self.assertEqual(self.registry["all_feature_library_tests"], 836)
        self.assertEqual(sum(self.registry["public_definition_totals"].values()), 446)

    def test_module_source_and_test_bijection_is_exact(self) -> None:
        registered = {Path(row["source"]).relative_to(
            "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/src"
        ).as_posix() for row in self.registry["modules"]}
        discovered = {
            path.relative_to(SOURCE_ROOT).as_posix()
            for path in SOURCE_ROOT.rglob("*.rs")
            if path.name != "lib.rs"
        }
        self.assertEqual(registered, discovered)
        self.assertEqual(
            sum(row["tests_all_features"] for row in self.registry["modules"]),
            836,
        )

    def test_profiles_features_and_dependencies_are_exact(self) -> None:
        profiles = {row["name"]: row for row in self.registry["profiles"]}
        self.assertEqual(
            {name: row["library_tests"] for name, row in profiles.items()},
            {
                "v1_only": 542,
                "sv2_only": 802,
                "default": 829,
                "scrypt_l7": 834,
                "mock_default": 831,
                "all_features": 836,
            },
        )
        self.assertEqual(
            self.registry["features"],
            {
                "default": ["sv2", "jd"],
                "sv2": ["dep:chacha20poly1305", "dep:secp256k1", "dep:rand_core"],
                "jd": ["sv2"],
                "scrypt-l7": [],
                "mock-pool": ["sv2"],
            },
        )
        self.assertNotIn("k256", self.registry["direct_dependencies"])
        self.assertNotIn("sv2-pure-rust", self.registry["features"])

    def test_public_surface_and_consumers_are_exact(self) -> None:
        self.assertEqual(len(self.registry["root_surface"]["public_modules"]), 16)
        self.assertEqual(len(self.registry["root_surface"]["public_use_statements"]), 8)
        self.assertEqual(self.registry["direct_consumers"], DIRECT_CONSUMERS)
        for rel in DIRECT_CONSUMERS:
            manifest = REPO_ROOT / rel / "Cargo.toml"
            self.assertIn(
                "dcentrald-stratum",
                manifest.read_text(encoding="utf-8"),
                rel,
            )

    def test_network_authentication_and_test_subprocess_fail_closed(self) -> None:
        root = (SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")
        auth = (SOURCE_ROOT / "v2" / "auth.rs").read_text(encoding="utf-8")
        client = (SOURCE_ROOT / "v2" / "client.rs").read_text(encoding="utf-8")
        jd = (SOURCE_ROOT / "v2" / "jd.rs").read_text(encoding="utf-8")
        manifest = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", root)
        self.assertIn("admit_authority_key_for_peer(&pool.url, peer_is_loopback)", client)
        self.assertIn("admit_authority_key_for_peer(url, peer_is_loopback)", jd)
        self.assertIn("SV2 cleartext override requires an actual loopback peer", auth)
        self.assertIn("address.ip().is_loopback()", client)
        self.assertIn("address.ip().is_loopback()", jd)
        self.assertIn('std::env::var("DCENT_SV2_JD_REGTEST_BITCOIND").ok()?', jd)
        self.assertNotIn('"/usr/bin/bitcoind"', jd)
        self.assertNotIn('"bitcoind".into()', jd)
        self.assertNotIn("sv2-pure-rust", manifest)
        self.assertNotIn("k256", manifest)

    def test_production_has_no_unsafe_filesystem_or_subprocess_path(self) -> None:
        source_files = list(SOURCE_ROOT.rglob("*.rs"))
        combined = "\n".join(path.read_text(encoding="utf-8") for path in source_files)
        self.assertNotRegex(combined, r"\bunsafe\s*\{")
        for path in source_files:
            text = path.read_text(encoding="utf-8")
            markers = [match.start() for match in re.finditer(r"std::(?:fs|process)::", text)]
            if not markers:
                continue
            test_module = re.search(r"#\[cfg\(test\)\]\s*mod\s+tests\s*\{", text)
            self.assertIsNotNone(test_module, path)
            self.assertTrue(all(pos > test_module.start() for pos in markers), path)

    def test_hardware_ledger_cannot_borrow_network_maturity(self) -> None:
        ledger_text = LEDGER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("dcentrald-stratum", ledger_text)
        self.assertTrue(all(not row["ledger_rows"] for row in self.registry["modules"]))

    def test_workflow_aggregate_and_campaign_own_the_surface(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald-stratum --lib", workflow)
        self.assertIn("cargo test --locked -p dcentrald-stratum --no-default-features --lib", workflow)
        self.assertIn("cargo test --locked -p dcentrald-stratum --features scrypt-l7 --lib", workflow)
        self.assertIn("cargo test --locked -p dcentrald-stratum --features mock-pool", workflow)
        self.assertIn("scripts/test_dcentrald_stratum_module_registry.py -q", aggregate)
        self.assertIn("Stratum crate registry convergence", campaign)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-registry", action="store_true")
    arguments, remaining = parser.parse_known_args()
    if arguments.write_registry:
        REGISTRY_PATH.write_bytes(
            (json.dumps(build_registry(), indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        print(REGISTRY_PATH)
        return 0
    unittest_args = [__file__, *remaining]
    result = unittest.main(argv=unittest_args, exit=False)
    return 0 if result.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
