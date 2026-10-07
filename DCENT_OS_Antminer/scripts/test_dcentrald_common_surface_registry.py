#!/usr/bin/env python3
"""Pin the complete dcentrald-common contract and narrow effect surface."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
WORKSPACE_ROOT = DCENTOS_ROOT / "dcentrald"
CRATE_ROOT = WORKSPACE_ROOT / "dcentrald-common"
SOURCE_ROOT = CRATE_ROOT / "src"
TEST_ROOT = CRATE_ROOT / "tests"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_common_surface_registry.json"
)

PUBLIC_PATTERNS = {
    "structs": r"^\s*pub\s+struct\s+",
    "enums": r"^\s*pub\s+enum\s+",
    "traits": r"^\s*pub\s+trait\s+",
    "type_aliases": r"^\s*pub\s+type\s+",
    "functions_and_methods": r"^\s*pub(?:\s+(?:async|const|unsafe))*\s+fn\s+",
    "constants": r"^\s*pub\s+const\s+",
    "statics": r"^\s*pub\s+static\s+",
    "module_declarations": r"^\s*pub\s+mod\s+",
    "use_declarations": r"^\s*pub\s+use\s+",
}

PRODUCTION_EFFECT_PATTERNS = {
    "filesystem": r"\bstd::fs::|\buse\s+std::fs\b",
    "environment": r"\bstd::env::",
    "network": r"\bstd::net::|\btokio::net::|\basync_std::net::",
    "subprocess": r"\bstd::process::Command\b|\bCommand::new\s*\(",
    "async_runtime": r"\btokio::|\basync_std::",
    "ffi": r"\blibc::|extern\s+\"C\"",
    "device_path_literals": r"[\"']/dev/",
}

UNSAFE_CODE_PATTERNS = (
    r"\bunsafe\s*\{",
    r"\bunsafe\s+fn\b",
    r"\bunsafe\s+impl\b",
    r"\bunsafe\s+trait\b",
    r"extern\s+\"C\"",
)

PRODUCTION_FILESYSTEM_MODULES = [
    "atomic_file",
    "mutation_disposition",
    "s19k_bm1366_wire_b",
    "thermal_lockout",
]

RECOVERY_TOOL_MODULES = [
    "bm1396_pic",
    "bm1485_l3plus_pic_firmware",
    "bm1485_l3plus_stock_pic",
    "lib",
]

DIRECT_CONSUMERS = [
    "dcentrald",
    "dcentrald-api",
    "dcentrald-api-types",
    "dcentrald-asic",
    "dcentrald-autotuner",
    "dcentrald-diagnostics",
    "dcentrald-hal",
    "dcentrald-silicon-profiles",
    "dcentrald-stratum",
    "dcentrald-thermal",
    "fuzz",
]


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def public_census(text: str) -> dict[str, int]:
    return {
        name: len(re.findall(pattern, text, re.MULTILINE))
        for name, pattern in PUBLIC_PATTERNS.items()
    }


def test_count(text: str) -> int:
    return len(
        re.findall(r"^\s*#\[(?:(?:tokio|async_std)::)?test\]\s*$", text, re.MULTILINE)
    )


def recovery_tool_test_count(text: str) -> int:
    return len(
        re.findall(
            r'^\s*#\[cfg\(feature\s*=\s*"recovery-tool"\)\]\s*\n'
            r"\s*#\[test\]\s*$",
            text,
            re.MULTILINE,
        )
    )


def non_unix_test_count(text: str) -> int:
    pattern = re.compile(
        r"^#\[cfg\(all\(test,\s*not\(unix\)\)\)\]\s*\n"
        r"mod\s+[A-Za-z0-9_]+\s*\{(?P<body>.*?)^\}",
        re.MULTILINE | re.DOTALL,
    )
    return sum(test_count(match.group("body")) for match in pattern.finditer(text))


def benchmark_count(text: str) -> int:
    return len(re.findall(r"^\s*#\[bench\]\s*$", text, re.MULTILINE))


def production_text(text: str) -> str:
    match = re.search(r"^\s*#\[cfg\(test\)\]\s*$", text, re.MULTILINE)
    return text[: match.start()] if match else text


def production_effects(text: str) -> list[str]:
    production = production_text(text)
    return [
        name
        for name, pattern in PRODUCTION_EFFECT_PATTERNS.items()
        if re.search(pattern, production)
    ]


def unsafe_code_count(text: str) -> int:
    return sum(len(re.findall(pattern, text)) for pattern in UNSAFE_CODE_PATTERNS)


def module_family(name: str) -> str:
    if name == "lib":
        return "crate_root"
    families = (
        "bm1385",
        "bm1391",
        "bm1396",
        "bm1397",
        "bm1398",
        "bm1485",
        "bm1489",
        "bm1491",
        "s19k",
        "s21",
        "s9se",
        "s9_",
        "t21",
        "x17",
        "x19",
        "xil",
    )
    for prefix in families:
        if name.startswith(prefix):
            return prefix.rstrip("_")
    return "shared_contract"


def source_paths() -> list[Path]:
    root = SOURCE_ROOT / "lib.rs"
    return [root, *sorted(path for path in SOURCE_ROOT.glob("*.rs") if path != root)]


def private_test_children() -> dict[str, str]:
    """Account for the exact compiled test child without making it public."""
    children = {"bm1393_native_tests": "bm1393_native"}
    for child, parent in children.items():
        source = (SOURCE_ROOT / f"{parent}.rs").read_text(encoding="utf-8")
        marker = f'#[cfg(test)]\n#[path = "{child}.rs"]\nmod tests;'
        if marker not in source:
            raise AssertionError(f"private test-child binding drifted: {parent}/{child}")
    return children


def generated_source_includes() -> dict[str, str]:
    """Bind generated source fragments without counting them as public modules."""
    fragments = {"amlogic_gpio437_table": "amlogic_gpio437"}
    for child, parent in fragments.items():
        source = (SOURCE_ROOT / f"{parent}.rs").read_text(encoding="utf-8")
        if f'include!("{child}.rs");' not in source:
            raise AssertionError(f"generated source binding drifted: {parent}/{child}")
    return fragments


def integration_paths() -> list[Path]:
    return sorted(TEST_ROOT.rglob("*.rs"))


def canonical_tree_sha256(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        raw = path.read_bytes()
        digest.update(relative(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
    return digest.hexdigest().upper()


def source_row(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    return {
        "module": path.stem,
        "source": relative(path),
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "surface_family": module_family(path.stem),
        "public_definition_census": public_census(text),
        "test_attributes": test_count(text),
        "recovery_tool_test_attributes": recovery_tool_test_count(text),
        "non_unix_test_attributes": non_unix_test_count(text),
        "benchmark_attributes": benchmark_count(text),
        "unsafe_code_constructs": unsafe_code_count(text),
        "production_effects": production_effects(text),
        "recovery_tool_cfg_attributes": len(
            re.findall(r"#\[cfg\(feature\s*=\s*\"recovery-tool\"\)\]", text)
        ),
    }


def manifest_section_keys(text: str, section: str) -> list[str]:
    active = False
    keys: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == f"[{section}]"
            continue
        if active and "=" in line:
            key = line.split("=", 1)[0].strip()
            if key.endswith(".workspace"):
                key = key.removesuffix(".workspace")
            keys.append(key)
    return sorted(keys)


def observed_consumers() -> list[str]:
    consumers = []
    for candidate in WORKSPACE_ROOT.iterdir():
        manifest = candidate / "Cargo.toml"
        if candidate == CRATE_ROOT or not manifest.is_file():
            continue
        text = manifest.read_text(encoding="utf-8")
        if re.search(r"^dcentrald-common\s*=", text, re.MULTILINE):
            consumers.append(candidate.name)
    return sorted(consumers)


def recovery_feature_forwarders() -> list[str]:
    consumers = []
    for candidate in WORKSPACE_ROOT.iterdir():
        manifest = candidate / "Cargo.toml"
        if candidate == CRATE_ROOT or not manifest.is_file():
            continue
        text = manifest.read_text(encoding="utf-8")
        declaration = re.search(r"^dcentrald-common\s*=.*$", text, re.MULTILINE)
        direct_feature = declaration and "recovery-tool" in declaration.group(0)
        forwarded_feature = "dcentrald-common/recovery-tool" in text
        if direct_feature or forwarded_feature:
            consumers.append(candidate.name)
    return sorted(consumers)


def build_registry() -> dict[str, object]:
    sources = source_paths()
    integrations = integration_paths()
    rows = [source_row(path) for path in sources]
    integration_rows = [source_row(path) for path in integrations]
    manifest_text = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    family_counts = Counter(str(row["surface_family"]) for row in rows)
    effect_owners: dict[str, list[str]] = {}
    for effect in PRODUCTION_EFFECT_PATTERNS:
        effect_owners[effect] = sorted(
            str(row["module"]) for row in rows if effect in row["production_effects"]
        )
    public_totals = {
        key: sum(int(row["public_definition_census"][key]) for row in rows)
        for key in PUBLIC_PATTERNS
    }
    recovery_modules = sorted(
        str(row["module"])
        for row in rows
        if int(row["recovery_tool_cfg_attributes"]) > 0
    )
    unit_test_attributes = sum(int(row["test_attributes"]) for row in rows)
    recovery_tool_test_attributes = sum(
        int(row["recovery_tool_test_attributes"]) for row in rows
    )
    non_unix_test_attributes = sum(int(row["non_unix_test_attributes"]) for row in rows)
    integration_test_attributes = sum(
        int(row["test_attributes"]) for row in integration_rows
    )
    unix_default_unit_tests = (
        unit_test_attributes - recovery_tool_test_attributes - non_unix_test_attributes
    )
    unix_recovery_unit_tests = unit_test_attributes - non_unix_test_attributes

    return {
        "schema_version": 1,
        "generated": "2026-09-07",
        "crate": "dcentrald-common",
        "crate_root": relative(CRATE_ROOT),
        "authority_ceiling": (
            "Shared schemas, pure planners, offline evidence, bounded state-file "
            "helpers, and successful host tests do not prove deployed-unit identity, "
            "carrier wiring, live transport, sensor truth, actuator custody, a safe "
            "operating point, work delivery, accepted shares, flash success, reboot, "
            "recovery, or mining readiness."
        ),
        "source_policy": {
            "rust_source_files": len(sources),
            "declared_public_modules": len(sources) - 1 - len(private_test_children()) - len(generated_source_includes()),
            "source_bytes": sum(int(row["bytes"]) for row in rows),
            "source_tree_sha256": canonical_tree_sha256(sources),
            "public_definition_census": public_totals,
            "lexical_public_items": sum(public_totals.values()),
            "unit_test_attributes": unit_test_attributes,
            "benchmark_attributes": sum(
                int(row["benchmark_attributes"]) for row in rows
            ),
            "unsafe_code_constructs": sum(
                int(row["unsafe_code_constructs"]) for row in rows
            ),
            "surface_family_counts": dict(sorted(family_counts.items())),
            "production_effect_owners": effect_owners,
        },
        "sources": rows,
        "private_test_children": private_test_children(),
        "generated_source_includes": generated_source_includes(),
        "integration_tests": {
            "files": integration_rows,
            "test_attributes": integration_test_attributes,
            "bytes": sum(int(row["bytes"]) for row in integration_rows),
            "tree_sha256": canonical_tree_sha256(integrations),
        },
        "complete_rust_tree": {
            "files": len(sources) + len(integrations),
            "bytes": sum(int(row["bytes"]) for row in [*rows, *integration_rows]),
            "test_attributes": sum(
                int(row["test_attributes"]) for row in [*rows, *integration_rows]
            ),
            "tree_sha256": canonical_tree_sha256([*sources, *integrations]),
        },
        "manifest": {
            "direct_dependencies": manifest_section_keys(manifest_text, "dependencies"),
            "dev_dependencies": manifest_section_keys(
                manifest_text, "dev-dependencies"
            ),
            "features": manifest_section_keys(manifest_text, "features"),
            "feature_profiles": {
                "default": {
                    "enabled_features": [],
                    "target_cfg": "unix",
                    "expected_unit_harness_tests": unix_default_unit_tests,
                    "expected_package_harness_tests": (
                        unix_default_unit_tests + integration_test_attributes
                    ),
                    "authority_ceiling": (
                        "Destructive PIC recovery planner symbols are absent."
                    ),
                },
                "recovery-tool": {
                    "enabled_features": ["recovery-tool"],
                    "target_cfg": "unix",
                    "expected_unit_harness_tests": unix_recovery_unit_tests,
                    "expected_package_harness_tests": (
                        unix_recovery_unit_tests + integration_test_attributes
                    ),
                    "authority_ceiling": (
                        "Feature-gated PIC command and flash planners remain pure "
                        "descriptions with no transport, device, execution, install, "
                        "or recovery authority."
                    ),
                },
                "lab": {
                    "enabled_features": ["lab"],
                    "target_cfg": "unix",
                    "expected_unit_harness_tests": unix_default_unit_tests,
                    "expected_package_harness_tests": (
                        unix_default_unit_tests + integration_test_attributes
                    ),
                    "authority_ceiling": (
                        "Compile-time hardware environment readers are enabled; "
                        "this capability cannot authorize signed Beta/Stable runtime. "
                        "Destructive PIC recovery planner symbols remain absent."
                    ),
                },
            },
            "recovery_tool_modules": recovery_modules,
            "recovery_tool_cfg_attributes": sum(
                int(row["recovery_tool_cfg_attributes"]) for row in rows
            ),
            "test_harness_census": {
                "lexical_unit_test_attributes": unit_test_attributes,
                "recovery_tool_unit_test_attributes": recovery_tool_test_attributes,
                "non_unix_only_unit_test_attributes": non_unix_test_attributes,
                "integration_test_attributes": integration_test_attributes,
            },
            "direct_consumers": observed_consumers(),
            "recovery_feature_forwarding_consumers": recovery_feature_forwarders(),
        },
        "safety_invariants": [
            (
                "The crate root forbids unsafe code; the complete source surface "
                "contains no unsafe construct or FFI boundary."
            ),
            (
                "Production filesystem effects are confined to four exact modules: "
                "atomic publication, mutation disposition, thermal lockout, and the "
                "S19k Bench-GO marker."
            ),
            (
                "No production source owns a network stack, subprocess runner, or "
                "async runtime. Device-path literals are evidence or policy strings, "
                "not device opens."
            ),
            (
                "The S19k Bench-GO marker admits only a regular non-symlink file; "
                "missing, unreadable, symlink, directory, and special objects refuse."
            ),
            (
                "The recovery-tool feature is default-off. The sole direct feature "
                "forwarder is dcentrald-hal's opt-in recovery-tool profile; no "
                "shipping daemon feature forwards it. Common's symbols remain pure "
                "planners, while the HAL owns any separate I/O authority."
            ),
            (
                "Module names, protocol bytes, register maps, firmware facts, and "
                "reconstructed state machines cannot borrow physical maturity from "
                "the capability ledger or from a runtime consumer."
            ),
        ],
        "known_external_blockers": [
            "No registry fact authenticates an attached miner, hashboard, control board, PSU, PIC, FPGA, EEPROM, sensor, fan, or rail.",
            "Pure transport and work planners do not prove framing, electrical levels, exclusivity, timing, cancellation, nonce binding, accepted shares, or payouts.",
            "Filesystem helpers still depend on trusted parent-directory custody and target-filesystem durability semantics.",
            "The Bench-GO environment variable remains ambient process authority; deployment must control the daemon environment.",
            "The regular-file marker check and later daemon action are not one descriptor-held transaction.",
            "Default-off recovery planners do not supply authentication, target identity, transport, readback, verification, rollback, or operator authorization.",
            "Host tests cannot establish target kernel, libc, storage, clock, concurrency, process-lifecycle, or power-loss behavior.",
            "No source-derived registry establishes safe voltage, frequency, current, power, fan, or thermal limits on a deployed unit.",
            "Evidence modules may name destructive commands and device paths without owning or authorizing their execution.",
            "Successful compilation and tests do not establish boot, update, recovery, mining, or shutdown outcomes.",
        ],
    }


class DcentraldCommonSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.expected = build_registry()

    def test_registry_is_exact_and_complete(self) -> None:
        self.assertEqual(self.registry, self.expected)
        policy = self.registry["source_policy"]
        self.assertEqual(policy["rust_source_files"], 160)
        self.assertEqual(policy["declared_public_modules"], 157)
        self.assertEqual(policy["unit_test_attributes"], 1643)
        self.assertEqual(policy["benchmark_attributes"], 0)
        self.assertEqual(policy["unsafe_code_constructs"], 0)
        self.assertEqual(self.registry["complete_rust_tree"]["files"], 164)
        self.assertEqual(self.registry["complete_rust_tree"]["test_attributes"], 1671)

    def test_module_declarations_and_sources_are_one_to_one(self) -> None:
        root_text = (SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")
        declared = set(
            re.findall(r"^pub mod ([A-Za-z0-9_]+);", root_text, re.MULTILINE)
        )
        # An explicit #[path] child is a real compiled module but is not a
        # root lib.rs declaration. Bind its parent, source and public alias.
        nested = []
        for parent in sorted(declared):
            text = (SOURCE_ROOT / f"{parent}.rs").read_text(encoding="utf-8")
            for child_source, alias in re.findall(
                r'#\[path\s*=\s*"([^"/]+\.rs)"\]\s*pub mod ([A-Za-z0-9_]+);', text
            ):
                nested.append((parent, child_source, alias))
        self.assertEqual(nested, [("s19_bm1398_runtime", "s19_bm1398_executor.rs", "executor")])
        declared.update(Path(child_source).stem for _, child_source, _ in nested)
        source_modules = {
            path.stem for path in SOURCE_ROOT.glob("*.rs") if path.name != "lib.rs"
        }
        children = private_test_children()
        self.assertEqual(self.registry["private_test_children"], children)
        fragments = generated_source_includes()
        self.assertEqual(self.registry["generated_source_includes"], fragments)
        children = {**children, **fragments}
        source_modules.difference_update(children)
        registered = {
            row["module"] for row in self.registry["sources"]
            if row["module"] != "lib" and row["module"] not in children
        }
        self.assertEqual(declared, source_modules)
        self.assertEqual(declared, registered)
        self.assertEqual(len(declared), 157)
        self.assertTrue(
            all(row["benchmark_attributes"] == 0 for row in self.registry["sources"])
        )

    def test_manifest_features_dependencies_and_consumers_are_exact(self) -> None:
        manifest = self.registry["manifest"]
        self.assertEqual(manifest["direct_dependencies"], ["dcent-schema", "sha2"])
        self.assertEqual(manifest["dev_dependencies"], ["proptest"])
        self.assertEqual(manifest["features"], ["default", "lab", "recovery-tool"])
        self.assertEqual(set(manifest["feature_profiles"]), set(manifest["features"]))
        self.assertEqual(manifest["direct_consumers"], DIRECT_CONSUMERS)
        self.assertEqual(
            manifest["recovery_feature_forwarding_consumers"], ["dcentrald-hal"]
        )
        self.assertNotIn("dcentrald", manifest["recovery_feature_forwarding_consumers"])

    def test_effect_and_unsafe_boundaries_are_exact_and_truthful(self) -> None:
        policy = self.registry["source_policy"]
        effects = policy["production_effect_owners"]
        self.assertEqual(effects["filesystem"], PRODUCTION_FILESYSTEM_MODULES)
        self.assertEqual(
            effects["environment"],
            ["atomic_file", "lab_env", "mutation_disposition"],
        )
        for forbidden in ("network", "subprocess", "async_runtime", "ffi"):
            self.assertEqual(effects[forbidden], [])
        root_text = (SOURCE_ROOT / "lib.rs").read_text(encoding="utf-8")
        manifest_text = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", root_text)
        self.assertNotIn("OS-free", root_text)
        self.assertNotIn("OS-free", manifest_text)
        self.assertIn("Filesystem effects are restricted", root_text)
        self.assertIn("Four audited", manifest_text)

    def test_recovery_feature_surface_is_default_off_and_non_authorizing(self) -> None:
        manifest = self.registry["manifest"]
        self.assertEqual(manifest["recovery_tool_modules"], RECOVERY_TOOL_MODULES)
        self.assertGreater(manifest["recovery_tool_cfg_attributes"], 0)
        self.assertEqual(
            manifest["test_harness_census"],
            {
                "lexical_unit_test_attributes": 1643,
                "recovery_tool_unit_test_attributes": 6,
                "non_unix_only_unit_test_attributes": 2,
                "integration_test_attributes": 28,
            },
        )
        default = manifest["feature_profiles"]["default"]
        recovery = manifest["feature_profiles"]["recovery-tool"]
        self.assertEqual(default["target_cfg"], "unix")
        self.assertEqual(default["expected_unit_harness_tests"], 1635)
        self.assertEqual(default["expected_package_harness_tests"], 1663)
        self.assertEqual(recovery["target_cfg"], "unix")
        self.assertEqual(recovery["expected_unit_harness_tests"], 1641)
        self.assertEqual(recovery["expected_package_harness_tests"], 1669)
        lab = manifest["feature_profiles"]["lab"]
        self.assertEqual(lab["expected_unit_harness_tests"], 1635)
        self.assertEqual(lab["expected_package_harness_tests"], 1663)
        self.assertIn("cannot authorize signed Beta/Stable", lab["authority_ceiling"])
        for row in self.registry["sources"]:
            if row["module"] in RECOVERY_TOOL_MODULES:
                self.assertNotIn("network", row["production_effects"])
                self.assertNotIn("subprocess", row["production_effects"])
                self.assertNotIn("ffi", row["production_effects"])
        ceiling = manifest["feature_profiles"]["recovery-tool"]["authority_ceiling"]
        for word in ("pure", "no transport", "recovery authority"):
            self.assertIn(word, ceiling)

    def test_integration_surface_is_exact(self) -> None:
        rows = self.registry["integration_tests"]["files"]
        self.assertEqual([row["module"] for row in rows], [
            "addr_interval_declared_with_fallback", "am1_dspic_session_replay",
            "lab_env", "runtime_hardware_recipe",
        ])
        self.assertEqual(self.registry["integration_tests"]["test_attributes"], 28)
        self.assertTrue(all(row["unsafe_code_constructs"] == 0 for row in rows))

    def test_bench_go_marker_is_regular_file_only_and_fail_closed(self) -> None:
        source = (SOURCE_ROOT / "s19k_bm1366_wire_b.rs").read_text(encoding="utf-8")
        self.assertIn("std::fs::symlink_metadata(file_path)", source)
        self.assertIn("metadata.file_type().is_file()", source)
        self.assertIn("!metadata.file_type().is_symlink()", source)
        self.assertNotIn("match std::fs::metadata(file_path)", source)
        self.assertIn("utf8 temp directory", source)
        self.assertIn("temp marker symlink", source)

    def test_workflow_aggregate_and_campaign_own_the_complete_surface(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "cargo test --locked -p dcentrald-common --all-features "
            "--no-fail-fast -- --test-threads=1",
            workflow,
        )
        self.assertIn(
            "python3 scripts/test_dcentrald_common_surface_registry.py -q",
            workflow,
        )
        offline_job = re.search(
            r"(?ms)^  offline-gates:\s*$.*?^    timeout-minutes:\s*(\d+)\s*$",
            workflow,
        )
        self.assertIsNotNone(offline_job)
        self.assertGreaterEqual(
            int(offline_job.group(1)),
            40,
            "the complete common suite needs explicit hosted-job headroom",
        )
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_dcentrald_common_surface_registry.py -q", aggregate)
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Common contract surface authority registry", campaign)


def summary(registry: dict[str, object]) -> dict[str, object]:
    policy = registry["source_policy"]
    integrations = registry["integration_tests"]
    complete = registry["complete_rust_tree"]
    manifest = registry["manifest"]
    return {
        "source_files": policy["rust_source_files"],
        "source_bytes": policy["source_bytes"],
        "source_tree_sha256": policy["source_tree_sha256"],
        "public_items": policy["lexical_public_items"],
        "unit_test_attributes": policy["unit_test_attributes"],
        "integration_files": len(integrations["files"]),
        "integration_test_attributes": integrations["test_attributes"],
        "complete_files": complete["files"],
        "complete_bytes": complete["bytes"],
        "complete_test_attributes": complete["test_attributes"],
        "complete_tree_sha256": complete["tree_sha256"],
        "recovery_tool_cfg_attributes": manifest["recovery_tool_cfg_attributes"],
        "direct_consumers": len(manifest["direct_consumers"]),
        "effect_owners": policy["production_effect_owners"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-registry-hex", action="store_true")
    parser.add_argument("--write-registry", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--length", type=int, default=6000)
    args, remaining = parser.parse_known_args()
    if args.emit_registry_hex:
        raw = json.dumps(build_registry(), indent=2, ensure_ascii=True).encode("ascii")
        encoded = raw.hex()
        print(encoded[args.start : args.start + args.length])
        print(f"HEX_TOTAL={len(encoded)}", file=__import__("sys").stderr)
        return 0
    if args.write_registry:
        REGISTRY_PATH.write_text(
            json.dumps(build_registry(), indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
            newline="\n",
        )
        return 0
    if args.summary:
        print(json.dumps(summary(build_registry()), indent=2))
        return 0
    program = unittest.main(argv=[__file__, *remaining], exit=False)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
