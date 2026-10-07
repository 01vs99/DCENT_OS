#!/usr/bin/env python3
"""Pin the complete host-safe dcentrald-api-types module surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentrald-api-types"
SOURCE_ROOT = CRATE_ROOT / "src"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_api_types_module_registry.json"
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
    "functions_and_methods": (
        r"^\s*pub(?:\s+(?:async|const|unsafe))*\s+fn\s+"
    ),
    "constants": r"^pub const\s+",
    "statics": r"^pub static\s+",
}

CODEC_PARSER_MODULES = set(
    """audit_log bm1366_eeprom bm1398_get_address deployed_eeprom
    dspic_frame eeprom_record hashboard_eeprom ip_reporter luxos_audit_log
    luxos_response_payloads luxos_rest_envelope metrics_csv
    prometheus_metrics remote_temp_sensor stratum_v1_messages
    stratum_v2_channel_responses stratum_v2_messages
    stratum_v2_mining_messages uart_trans_layout whatsminer_btminer
    zhiju_eeprom""".split()
)
CLASSIFIER_PLANNER_MODULES = set(
    """asic_command autotune_policy baud_switch bm13xx_pll cold_environment
    diode_voltage frequency_scaling hashboard_diagnostics perf_efficiency
    power_model power_profile_preset psu_bypass ramp_curve sensor_outlier
    share_validation thermal_model work_dispatch""".split()
)
STATE_MACHINE_MODULES = set(
    """atm_stepper autotune_phase boot_flow boot_orchestration failure_mode
    hashrate_recovery luxos_pool_failover mining_loop_state
    ota_rollback_protection power_state watchdog_policy""".split()
)
TOPOLOGY_IDENTITY_MODULES = set(
    """apw_dual_output asic_protocol_spec asic_register_map
    bm1368_temperature bm1398_protocol bm139x_get_address chip_init
    fpga_bitstream fpga_register_map psu_apw_protocol psu_maintenance
    psu_model xil_dual_chain_desk_map""".split()
)

LEDGER_ROWS = {
    "baud_switch": ["asic.bm1485"],
    "bm1398_protocol": ["asic.bm1398"],
    "deployed_eeprom": ["asic.bm1398", "eeprom.fmt45"],
    "eeprom_record": ["eeprom.fmt45", "eeprom.unresolved_formats"],
    "firmware_boot_timeline": ["bootloader.timeline_registry"],
    "fpga_bitstream": ["fpga.source_evidence_registry", "cpld.negative_census"],
    "hashboard_eeprom": ["asic.bm1398"],
    "remote_temp_sensor": ["sensor.temperature_catalogs"],
}

ROOT_STRUCTS = ["ApiErrorBody", "RecentShareRow", "MiningPipelineSnapshot"]
ROOT_ENUMS = [
    "OperatingMode",
    "MiningPipelineFreshnessClassifierStatus",
    "MiningPipelineSnapshotStatus",
]
ROOT_FUNCTIONS_AND_METHODS = [
    "from_config_str",
    "is_home",
    "allows_debug",
    "allows_stats",
    "requires_confirmation",
    "new",
    "with_code",
    "with_suggestion",
    "with_detail",
    "classify_domain_timestamp",
    "as_snapshot_status",
    "classify_freshness",
    "unavailable",
    "normalize_freshness",
    "freshness_fixture",
    "eeprom_write_denied",
]
ROOT_CONSTANTS = [
    "MINING_PIPELINE_SNAPSHOT_SCHEMA",
    "MINING_PIPELINE_FRESHNESS_CLASSIFIER_SCHEMA",
    "RECENT_SHARE_ROW_SCHEMA",
    "API_CONTRACT_VERSION",
    "MINING_PIPELINE_SNAPSHOT_DEFAULT_STALE_AFTER_MS",
    "MINING_PIPELINE_FRESHNESS_DEFAULT_MAX_FUTURE_SKEW_MS",
    "EEPROM_WRITE_DENYLIST",
    "EEPROM_DENYLIST_PLATFORMS",
]
API_ERROR_CODES = [
    "CONFIG_VALIDATION",
    "ERROR_BODY_UNAVAILABLE",
    "LEGACY_ERROR",
    "POOL_CONFIG_WRITE_FAILED",
    "POOL_VALIDATION",
    "UNCLASSIFIED_ERROR",
]

DIRECT_CONSUMERS = [
    "dcentrald",
    "dcentrald-api",
    "dcentrald-api-grpc",
    "dcentrald-asic",
    "dcentrald-autotuner",
    "dcentrald-hal",
    "dcentrald-silicon-profiles",
    "dcentrald-stratum",
    "dcentrald-thermal",
]

INVARIANT_MACROS = [
    {
        "source": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/"
            "bm1398_get_address.rs"
        ),
        "macro": "expect",
        "count": 1,
        "boundary": (
            "Exact seven-byte length is checked before converting the six-byte "
            "prefix; malformed lengths already return a typed error."
        ),
    },
    {
        "source": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/"
            "bm1398_protocol.rs"
        ),
        "macro": "panic",
        "count": 2,
        "boundary": (
            "Compile-time construction of the two built-in literal address plans "
            "(NBP1901 0/114/2 and the shared 76-chip 0/76/3 for NBS1902/NBT1903); "
            "invalid literals fail compilation and no caller input reaches them."
        ),
    },
    {
        "source": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/psu_model.rs"
        ),
        "macro": "unreachable",
        "count": 2,
        "boundary": (
            "Nested APW12 revision labels are exhaustively constrained by their "
            "enclosing enum match arms; no untrusted discriminant can be constructed."
        ),
    },
    {
        "source": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/"
            "xil_dual_chain_desk_map.rs"
        ),
        "macro": "expect",
        "count": 1,
        "boundary": (
            "Desk-only helper admits two internally generated exact 114-frame "
            "BM1398 windows and has no live transport or production caller."
        ),
    },
]


def public_census(text: str) -> dict[str, int]:
    return {
        name: len(re.findall(pattern, text, re.MULTILINE))
        for name, pattern in PUBLIC_PATTERNS.items()
    }


def test_count(text: str) -> int:
    return len(re.findall(r"^\s*#\[test\]\s*$", text, re.MULTILINE))


def surface_class(name: str) -> str:
    if name == "bb_factory_profile_tests":
        return "test_fixture"
    if name == "bb_factory_profile":
        return "topology_identity"
    if name in CODEC_PARSER_MODULES:
        return "codec_parser"
    if name in CLASSIFIER_PLANNER_MODULES:
        return "classifier_planner"
    if name in STATE_MACHINE_MODULES:
        return "state_machine"
    if name in TOPOLOGY_IDENTITY_MODULES:
        return "topology_identity"
    return "dto_catalog"


def rust_sources() -> tuple[Path, list[Path]]:
    root = SOURCE_ROOT / "lib.rs"
    modules = sorted(path for path in SOURCE_ROOT.glob("*.rs") if path != root)
    return root, modules


def private_test_children() -> dict[str, str]:
    children = {"bb_factory_profile_tests": "bb_factory_profile"}
    for child, parent in children.items():
        source = (SOURCE_ROOT / f"{parent}.rs").read_text(encoding="utf-8")
        marker = f'#[cfg(test)]\n#[path = "{child}.rs"]\nmod tests;'
        if marker not in source:
            raise AssertionError(f"private test-child binding drifted: {parent}/{child}")
    return children


def build_registry() -> dict[str, object]:
    root_path, module_paths = rust_sources()
    root_text = root_path.read_text(encoding="utf-8")
    rows = []
    texts = [root_text]
    for path in module_paths:
        text = path.read_text(encoding="utf-8")
        texts.append(text)
        rows.append(
            {
                "module": path.stem,
                "source": (
                    "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/"
                    f"{path.name}"
                ),
                "tests": test_count(text),
                "public_definition_census": public_census(text),
                "surface_class": surface_class(path.stem),
                "ledger_rows": LEDGER_ROWS.get(path.stem, []),
            }
        )

    return {
        "schema_version": 1,
        "generated": "2026-08-20",
        "crate": "dcentrald-api-types",
        "crate_root": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/src/lib.rs"
        ),
        "authority_ceiling": (
            "Pure API DTOs, catalogs, codecs, classifiers, planners, and host "
            "tests do not prove a deployed miner, physical silicon or carrier "
            "identity, fresh telemetry, trusted configuration, safe operating "
            "point, actuator custody, work delivery, accepted shares, "
            "persistence, networking, reboot, or any hardware operation."
        ),
        "ledger_scope_reason": (
            "Only modules named by an existing hardware-capability ledger source "
            "claim that row. Empty module scopes are intentional: API vocabulary "
            "and reconstructed catalogs cannot borrow hardware maturity merely "
            "because a consumer may display or delegate their values."
        ),
        "source_policy": {
            "rust_source_files": len(module_paths) + 1,
            "declared_public_modules": len(module_paths) - len(private_test_children()),
            "features": [],
            "unsafe_blocks": 0,
            "forbidden_runtime_surfaces": [
                "filesystem",
                "network",
                "subprocess",
                "async runtime",
                "FFI",
                "device nodes",
            ],
        },
        "surface_classes": {
            "test_fixture": (
                "Exact private cfg(test) child; its assertions and test-only "
                "macros grant no production API, identity, readiness, or hardware authority."
            ),
            "codec_parser": (
                "Byte/JSON/text codecs and parsers transform caller-owned data "
                "only; successful decoding does not authenticate origin, "
                "freshness, identity, transport, or hardware state."
            ),
            "classifier_planner": (
                "Pure classifiers and planners compute recommendations or bounded "
                "layouts only; they do not own measurements, admission, "
                "actuators, dispatch, or persistence."
            ),
            "state_machine": (
                "In-memory state machines model transitions only; they do not "
                "schedule runtime work, observe devices, enforce process liveness, "
                "or execute recovery."
            ),
            "topology_identity": (
                "Topology, identity, register, and protocol facts are "
                "evidence-scoped descriptions; they do not prove the attached "
                "unit, loaded firmware, address ownership, safe wiring, or "
                "executable route."
            ),
            "dto_catalog": (
                "DTOs, schemas, and catalogs define serialized vocabulary only; "
                "a represented capability, endpoint, mode, status, or command is "
                "not proof that it exists, is safe, or is authorized."
            ),
        },
        "modules": rows,
        "private_test_children": private_test_children(),
        "root_surface": {
            "nested_public_modules": {"api_error_codes": API_ERROR_CODES},
            "public_structs": ROOT_STRUCTS,
            "public_enums": ROOT_ENUMS,
            "public_functions_and_methods": ROOT_FUNCTIONS_AND_METHODS,
            "public_constants": ROOT_CONSTANTS,
            "public_definition_census": public_census(root_text),
            "test_prefix": "tests",
            "tests": test_count(root_text),
        },
        "public_definition_totals": public_census("\n".join(texts)),
        "module_tests": sum(row["tests"] for row in rows),
        "total_tests": sum(test_count(text) for text in texts),
        "benchmarks": 0,
        "direct_dependencies": ["dcentrald-common", "serde", "serde_json"],
        "dev_dependencies": ["serde_json"],
        "features": [],
        "direct_consumers": DIRECT_CONSUMERS,
        "explicit_production_invariant_macros": INVARIANT_MACROS,
        "safety_invariants": [
            (
                "The crate root forbids unsafe code and the source contains no "
                "filesystem, network, subprocess, async-runtime, FFI, or "
                "device-node implementation."
            ),
            (
                "The default mining-pipeline snapshot is unavailable, read-only, "
                "and owns no control, hardware-write, or filesystem-mutation claim."
            ),
            (
                "Future, missing, disabled, stale, and zero-window timestamp "
                "inputs do not become live snapshot evidence."
            ),
            (
                "Cross-chain imbalance classification rejects missing, negative, "
                "non-finite sample values and invalid, negative, inverted, or "
                "non-finite thresholds."
            ),
            (
                "The EEPROM denylist is defense in depth only; it does not "
                "replace HAL ownership or authorize an unknown-platform write."
            ),
            (
                "Cataloged command names, opcodes, URLs, register maps, recovery "
                "flows, and firmware layouts are descriptive and never execute "
                "in this crate."
            ),
        ],
        "known_external_blockers": [
            (
                "Host-safe API contracts cannot authenticate the source or "
                "freshness of values populated by runtime consumers."
            ),
            (
                "Several evidence catalogs describe protocols, endpoints, "
                "update/recovery flows, and control commands whose live authority "
                "remains outside this crate."
            ),
        ],
    }


def manifest_section_keys(text: str, section: str) -> set[str]:
    active = False
    keys: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == f"[{section}]"
            continue
        if active and "=" in line:
            key = line.split("=", 1)[0].strip()
            if key.endswith(".workspace"):
                key = key.removesuffix(".workspace")
            keys.add(key)
    return keys


def production_macro_census() -> dict[tuple[str, str], int]:
    patterns = {
        "unwrap": r"\.unwrap\s*\(",
        "expect": r"\.expect\s*\(",
        "panic": r"\bpanic!\s*\(",
        "unreachable": r"\bunreachable!\s*\(",
        "todo": r"\btodo!\s*\(",
        "unimplemented": r"\bunimplemented!\s*\(",
    }
    observed: dict[tuple[str, str], int] = {}
    _, module_paths = rust_sources()
    children = private_test_children()
    for path in [SOURCE_ROOT / "lib.rs", *module_paths]:
        if path.stem in children:
            continue
        production = path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
        for macro, pattern in patterns.items():
            count = len(re.findall(pattern, production))
            if count:
                observed[(path.name, macro)] = count
    return observed


class DcentraldApiTypesModuleRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.expected = build_registry()

    def test_registry_is_exact_and_complete(self) -> None:
        self.assertEqual(self.registry, self.expected)
        self.assertEqual(len(self.registry["modules"]), 92)
        self.assertEqual(self.registry["module_tests"], 1435)
        self.assertEqual(self.registry["root_surface"]["tests"], 37)
        self.assertEqual(self.registry["total_tests"], 1472)
        self.assertEqual(sum(self.registry["public_definition_totals"].values()), 1294)
        self.assertEqual(self.registry["source_policy"]["declared_public_modules"], 91)

    def test_declared_modules_sources_and_test_prefixes_are_one_to_one(self) -> None:
        root_text = (SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")
        declared = set(
            re.findall(r"^pub mod ([A-Za-z0-9_]+);", root_text, re.MULTILINE)
        )
        rows = {row["module"]: row for row in self.registry["modules"]}
        children = private_test_children()
        self.assertEqual(self.registry["private_test_children"], children)
        self.assertTrue(declared.isdisjoint(children))
        self.assertEqual(set(rows), declared | set(children))
        self.assertEqual(
            {path.stem for path in SOURCE_ROOT.glob("*.rs") if path.name != "lib.rs"},
            declared | set(children),
        )
        for name, row in rows.items():
            owned_tests = row["tests"] + sum(
                rows[child]["tests"] for child, parent in children.items() if parent == name
            )
            self.assertGreater(owned_tests, 0, name)
        self.assertEqual(self.registry["benchmarks"], 0)
        self.assertNotRegex("\n".join(path.read_text(encoding="utf-8") for path in SOURCE_ROOT.glob("*.rs")), r"#\[bench\]")

    def test_manifest_dependencies_features_and_consumers_are_exact(self) -> None:
        manifest = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertEqual(
            manifest_section_keys(manifest, "dependencies"),
            set(self.registry["direct_dependencies"]),
        )
        self.assertEqual(
            manifest_section_keys(manifest, "dev-dependencies"),
            set(self.registry["dev_dependencies"]),
        )
        self.assertNotIn("[features]", manifest)
        observed = []
        workspace = CRATE_ROOT.parent
        for candidate in workspace.iterdir():
            cargo = candidate / "Cargo.toml"
            if candidate == CRATE_ROOT or not cargo.is_file():
                continue
            text = cargo.read_text(encoding="utf-8")
            if re.search(r"^dcentrald-api-types\s*=", text, re.MULTILINE):
                observed.append(candidate.name)
        self.assertEqual(sorted(observed), self.registry["direct_consumers"])

    def test_host_safe_boundary_and_invariant_macros_are_exact(self) -> None:
        root_path, module_paths = rust_sources()
        sources = {
            path.name: path.read_text(encoding="utf-8")
            for path in [root_path, *module_paths]
        }
        self.assertIn("#![forbid(unsafe_code)]", sources["lib.rs"])
        combined = "\n".join(sources.values())
        for forbidden in (
            "use std::fs",
            "std::fs::",
            "use std::net",
            "std::net::",
            "use std::process",
            "std::process::",
            "tokio::",
            "unsafe {",
            "unsafe fn",
            'extern "C"',
        ):
            self.assertNotIn(forbidden, combined)
        expected = {
            (Path(row["source"]).name, row["macro"]): row["count"]
            for row in self.registry["explicit_production_invariant_macros"]
        }
        self.assertEqual(production_macro_census(), expected)
        self.assertNotIn("unwrap", {macro for _, macro in expected})
        self.assertNotIn("todo", {macro for _, macro in expected})
        self.assertNotIn("unimplemented", {macro for _, macro in expected})

    def test_ledger_scopes_exist_and_cannot_claim_production_maturity(self) -> None:
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        entries = {row["id"]: row for row in ledger["entries"]}
        for module in self.registry["modules"]:
            self.assertIn(module["surface_class"], self.registry["surface_classes"])
            for owner in module["ledger_rows"]:
                self.assertIn(owner, entries)
                self.assertIn(
                    entries[owner]["status"],
                    {"experimental", "evidence-insufficient"},
                )

    def test_fail_closed_root_and_nonfinite_threshold_anchors_remain(self) -> None:
        root = (SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")
        policy = (SOURCE_ROOT / "autotune_policy.rs").read_text(encoding="utf-8")
        diagnostics = (SOURCE_ROOT / "hashboard_diagnostics.rs").read_text(
            encoding="utf-8"
        )
        for needle in (
            "read_only: true",
            "control_actions: false",
            "hardware_writes: false",
            "filesystem_mutation: false",
            "publisher_enabled: false",
            "snapshot_available: false",
        ):
            self.assertIn(needle, root)
        self.assertIn("!warn.is_finite()", policy)
        self.assertIn("!critical.is_finite()", policy)
        self.assertIn("imbalance_classifier_refuses_non_finite_thresholds", policy)
        self.assertIn("first.saturating_sub(*last)", diagnostics)
        self.assertNotIn("domain_voltages_mv.first().unwrap()", diagnostics)
        self.assertIn(
            'platform == "am1-zynq" && (0x55..=0x57).contains(&addr)', root
        )
        self.assertIn("eeprom_write_denied_unknown_platform_fails_closed", root)
        self.assertNotIn("eeprom_write_denied_unknown_platform_fails_open", root)

    def test_workflow_aggregate_and_campaign_own_the_complete_surface(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "cargo test --locked -p dcentrald-api-types --lib", workflow
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "scripts/test_dcentrald_api_types_module_registry.py -q", aggregate
        )
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("API-types crate registry convergence", campaign)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-registry-hex", action="store_true")
    parser.add_argument("--write-registry", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--length", type=int, default=6000)
    args, remaining = parser.parse_known_args()
    if args.emit_registry_hex:
        raw = json.dumps(build_registry(), indent=2, ensure_ascii=True).encode(
            "ascii"
        )
        encoded = raw.hex()
        print(encoded[args.start : args.start + args.length])
        print(f"HEX_TOTAL={len(encoded)}", file=__import__("sys").stderr)
        return 0
    if args.write_registry:
        REGISTRY_PATH.write_text(
            json.dumps(build_registry(), indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        return 0
    program = unittest.main(argv=[__file__, *remaining], exit=False)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
