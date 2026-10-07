#!/usr/bin/env python3
"""Pin the complete source-level dcentrald daemon authority surface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
WORKSPACE_ROOT = DCENTOS_ROOT / "dcentrald"
CRATE_ROOT = WORKSPACE_ROOT / "dcentrald"
SOURCE_ROOT = CRATE_ROOT / "src"
TEST_ROOT = CRATE_ROOT / "tests"
MANIFEST_PATH = CRATE_ROOT / "Cargo.toml"
WORKSPACE_MANIFEST_PATH = WORKSPACE_ROOT / "Cargo.toml"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentrald_daemon_surface_registry.json"
)

TEST_ATTRIBUTE_RE = re.compile(
    r"^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]", re.MULTILINE
)
VISIBLE_FUNCTION_RE = re.compile(
    r"^\s*pub(?:\([^\)]*\))?\s+"
    r"(?:async\s+|const\s+|unsafe\s+)*fn\s+[A-Za-z0-9_]+",
    re.MULTILINE,
)
VISIBLE_ITEM_RE = re.compile(
    r"^\s*pub(?:\([^\)]*\))?\s+"
    r"(?:struct|enum|trait|type|const|static|mod)\s+[A-Za-z0-9_]+",
    re.MULTILINE,
)
MODULE_DECL_RE = re.compile(
    r"^\s*(pub(?:\([^\)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;", re.MULTILINE
)

EFFECT_PATTERNS = {
    "network": re.compile(
        r"TcpListener|TcpStream|UdpSocket|UnixListener|connect_async|rumqttc|reqwest",
        re.IGNORECASE,
    ),
    "process": re.compile(r"Command::|std::process|tokio::process|libc::kill", re.I),
    "filesystem": re.compile(
        r"std::fs|tokio::fs|OpenOptions|File::|read_to_string|write\(", re.I
    ),
    "ffi": re.compile(r"libc::|extern\s+\"C\"", re.I),
    "device": re.compile(
        r"/dev/|sysfs|/sys/|/proc/|gpio|i2c|uart|serial|mmio|uio", re.I
    ),
    "power_or_thermal": re.compile(
        r"power|voltage|psu|rail|fan|thermal|temperature|safe.?off", re.I
    ),
    "mining_or_work": re.compile(
        r"stratum|pool|share|nonce|hashrate|mining|work[_ -]?(?:tx|dispatch)", re.I
    ),
    "persistence_or_reboot": re.compile(
        r"atomic_write|journal|persist|reboot|restart|shutdown", re.I
    ),
}

ARTIFACT_CONSUMERS = {
    "dcentrald": [
        "br2_external_dcentos/board/amlogic/am3-s19jpro-aml/post-build.sh",
        "br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh",
        "br2_external_dcentos/board/amlogic/am3-s21/post-build.sh",
        "br2_external_dcentos/board/amlogic/am3-s21pro/post-build.sh",
        "br2_external_dcentos/board/amlogic/am3-s21xp/post-build.sh",
        "br2_external_dcentos/board/amlogic/am3-t21/post-build.sh",
        "br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh",
        "br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/post-build.sh",
        "br2_external_dcentos/board/zynq/am2-s17pro/post-build.sh",
        "br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh",
        "br2_external_dcentos/board/zynq/am2-s19pro/post-build.sh",
        "br2_external_dcentos/board/zynq/post-build.sh",
    ],
    "dcentos-discovery": [
        "br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh",
        "br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/post-build.sh",
    ],
}

INIT_CONSUMERS = [
    "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald",
    "br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald",
    "br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald",
    "br2_external_dcentos/board/zynq/am2-s19jpro/rootfs-overlay/etc/init.d/S82dcentrald",
    "br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/init.d/S82dcentrald",
    "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S82dcentrald",
]

AUTHORITY_CEILING = (
    "This registry proves the checked-in source shape of the two dcentrald package "
    "binaries: modules, dependencies, features, CLI vocabulary, runtime dispatch "
    "kinds, tests, conservative lexical effects, unsafe/libc boundaries, configuration "
    "admission, discovery behavior, and image consumers. It does not prove a deployed "
    "binary, target ABI, platform identity, listener custody, authenticated operator, "
    "pool identity, accepted share, sensor truth, exclusive device ownership, correct "
    "ASIC/FPGA/PIC/PSU response, electrical SafeOff, flash durability, reboot, rollback, "
    "or safe and profitable Bitcoin-mining operation."
)

LEDGER_SCOPE_REASON = (
    "The hardware capability ledger records evidence-backed physical maturity. The root "
    "daemon composes and delegates those capabilities but cannot create carrier, silicon, "
    "transport, power, cooling, boot, install, recovery, or mining evidence, so this "
    "software registry intentionally borrows no ledger row."
)

ACTION_SURFACES = [
    "CLI one-shots can read/write fan state, request SafeOff, or verify a bundle before normal startup; each remains explicit operator/process authority.",
    "Configuration, logs, profiles, capability markers, lifecycle journals, and mutation dispositions read or publish persistent state.",
    "HTTP, CGMiner, gRPC, MQTT, bridge, webhook, Job Declaration, Stratum, proxy, and discovery code opens listeners or outbound network sessions.",
    "BoardDesc, immutable platform identity, ASIC protocol, route receipts, execution fences, and mutation journals gate runtime construction.",
    "Standard, serial, S19j hybrid, AM3 BeagleBone, tap, stock-FPGA, and simulator branches select distinct chain/work ownership paths.",
    "FPGA/UIO/MMIO, serial/UART, I2C, GPIO/sysfs, PIC, ASIC, fan, PSU, voltage, rail, and thermal paths can observe or mutate physical state.",
    "Bosminer handoff and selected diagnostics use subprocess, procfs identity, pidfd, signal, wait, or bounded command execution.",
    "Panic hooks, watchdogs, task/thread guards, cancellation, closeout receipts, management-only parking, and restart code govern terminal lifecycle.",
    "dcentos-discovery broadcasts LAN identity, answers UDP discovery requests, reads proc/sysfs identity, and optionally observes a recovery-button GPIO.",
]

FEATURE_PROFILES = [
    {
        "profile": "default",
        "features": [],
        "authority": "Production orchestration surface; simulator and MQTT TLS passthrough remain disabled.",
    },
    {
        "profile": "lab",
        "features": ["lab"],
        "authority": "Compile-time laboratory hardware overrides require explicit --lab-runtime admission; the compiled capability cannot authorize signed Beta/Stable images.",
    },
    {
        "profile": "sim-hal",
        "features": ["sim-hal"],
        "authority": "Host-only emulation routed through dependency simulator features; Buildroot/release profiles must not enable it.",
    },
    {
        "profile": "mqtt-tls",
        "features": ["mqtt-tls"],
        "authority": "Passes rustls transport support to dcentrald-api; it does not provision roots, broker identity, or command authorization.",
    },
    {
        "profile": "all-features",
        "features": ["lab", "mqtt-tls", "sim-hal"],
        "authority": "Compilation/test union only; it is not a shipped runtime profile or hardware receipt.",
    },
]

KNOWN_EXTERNAL_BLOCKERS = [
    "The source and host-test census does not prove either binary was staged into a specific image, launched by PID 1, reachable through the deployed firewall, or matched to the intended physical controller.",
    "The default daemon contains real device, power, thermal, work, and process-control authority; this registry never invokes those paths and cannot prove their electrical or mechanical outcome.",
    "The exact unsafe census includes production process/device boundaries and private host-only local-PTY fixtures; source accounting and host compilation do not validate target libc, kernel, fd, scheduling, or physical hardware behavior.",
    "Configuration reads are now bounded, no-follow, nonblocking on Unix, opened-handle regular-file checked, and exact-NotFound classified, but parent-directory trust and non-Unix replacement races remain external assumptions.",
    "A safe parsed configuration does not establish honest platform markers, BoardDesc correctness, attached ASIC identity, UART routing, EEPROM population, PSU variant, cooling topology, or exclusive fabric custody.",
    "CLI one-shots intentionally precede normal configuration and runtime admission; invoking fan, SafeOff, handoff, or recovery verbs remains explicit operator authority requiring target-specific procedures.",
    "Management-only parking preserves API reachability after selected failures, but it does not itself prove that rails are off, accepted task graphs have retired, listeners are healthy, or recovery remains authenticated.",
    "Stratum, proxy, Job Declaration, MQTT, webhook, bridge, gRPC, REST, CGMiner, and discovery transports require separate hostile-network, credential, endpoint, TLS, and replay validation.",
    "dcentos-discovery deliberately discloses model, IP, MAC, hostname, platform, daemon status, and uptime on the LAN; interoperability is not confidentiality or peer authentication.",
    "Buildroot staging paths and init consumers prove source ownership only; they do not prove ELF architecture, static linkage, image freshness, filesystem permissions, startup ordering, or runtime health.",
    "The exact test inventory includes source-contract and local simulation fixtures; test names, counts, and passing results do not promote any hardware capability-ledger maturity.",
    "No software acknowledgement, lifecycle closeout, journal removal, telemetry sample, nonce, or accepted-share counter proves physical SafeOff, stable cooling, correct voltage, durable persistence, payout, or safe unattended mining.",
]


def relative_source(path: Path) -> str:
    return path.relative_to(CRATE_ROOT).as_posix()


def registry_source(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def source_files() -> list[Path]:
    return sorted(SOURCE_ROOT.rglob("*.rs"), key=relative_source)


def module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT)
    if relative == Path("main.rs"):
        return "dcentrald_bin"
    if relative == Path("bin/dcentos_discovery.rs"):
        return "dcentos_discovery_bin"
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "mod":
        parts.pop()
    return "::".join(parts)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_tree_sha256(files: list[Path], raw_by_source: dict[str, bytes]) -> str:
    rows = [
        f"{relative_source(path)}|{sha256_bytes(raw_by_source[relative_source(path)])}"
        for path in files
    ]
    return sha256_bytes("\n".join(rows).encode())


def toml_section(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)", text)
    if match is None:
        raise AssertionError(f"missing TOML section [{name}]")
    return match.group(1)


def toml_keys(section: str) -> list[str]:
    return sorted(
        match.group(1)
        for match in re.finditer(
            r"(?m)^([A-Za-z0-9_-]+)(?:\.workspace)?\s*=", section
        )
    )


def toml_string(section: str, key: str) -> str:
    match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^\"]*)"', section)
    if match is None:
        raise AssertionError(f"missing TOML string {key}")
    return match.group(1)


def toml_string_array(text: str, key: str) -> list[str]:
    match = re.search(rf"(?ms)^{re.escape(key)}\s*=\s*\[(.*?)\]", text)
    if match is None:
        raise AssertionError(f"missing TOML array {key}")
    return re.findall(r'"([^\"]+)"', match.group(1))


def toml_string_array_map(section: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for match in re.finditer(
        r"(?ms)^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", section
    ):
        result[match.group(1)] = re.findall(r'"([^\"]+)"', match.group(2))
    return result


def toml_string_map(section: str) -> dict[str, str]:
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'(?m)^([A-Za-z0-9_-]+)\s*=\s*"([^\"]*)"', section
        )
    }


def manifest_binaries(text: str) -> list[dict[str, str]]:
    return [
        {
            "name": toml_string(block, "name"),
            "path": toml_string(block, "path"),
        }
        for block in re.findall(r"(?ms)^\[\[bin\]\]\s*\n(.*?)(?=^\[|\Z)", text)
    ]


def source_metrics(path: Path, raw: bytes) -> dict[str, object]:
    text = raw.decode()
    return {
        "module": module_name(path),
        "source": registry_source(path),
        "bytes": len(raw),
        "test_attributes": len(TEST_ATTRIBUTE_RE.findall(text)),
        "unsafe_blocks": len(re.findall(r"\bunsafe\s*\{", text)),
        "visible_items": len(VISIBLE_FUNCTION_RE.findall(text))
        + len(VISIBLE_ITEM_RE.findall(text)),
    }


def file_metrics(path: Path, *, tests: bool) -> dict[str, object]:
    raw = path.read_bytes()
    result: dict[str, object] = {
        "source": registry_source(path),
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
    }
    if tests:
        result["test_attributes"] = len(TEST_ATTRIBUTE_RE.findall(raw.decode()))
    return result


def module_declarations(path: Path, text: str) -> list[dict[str, str]]:
    return [
        {
            "module": match.group(2),
            "visibility": (match.group(1) or "private").strip(),
        }
        for match in MODULE_DECL_RE.finditer(text)
    ]


def rust_string_array(text: str, name: str) -> list[str]:
    match = re.search(
        rf"(?ms)^const\s+{re.escape(name)}:[^=]+?=\s*&\[(.*?)^\];", text
    )
    if match is None:
        raise AssertionError(f"missing Rust array {name}")
    return re.findall(r'"([^\"]+)"', match.group(1))


def build_registry() -> dict[str, object]:
    files = source_files()
    raw_by_source = {relative_source(path): path.read_bytes() for path in files}
    sources = {key: raw.decode() for key, raw in raw_by_source.items()}
    rows = [source_metrics(path, raw_by_source[relative_source(path)]) for path in files]
    integration = [
        file_metrics(path, tests=True) for path in sorted(TEST_ROOT.glob("*.rs"))
    ]
    fixtures = [
        file_metrics(path, tests=False)
        for path in sorted(path for path in TEST_ROOT.rglob("*") if path.is_file() and path.suffix != ".rs")
    ]
    declaration_sources = [
        path
        for path in files
        if path.name == "mod.rs" or path == SOURCE_ROOT / "main.rs"
    ]
    declarations = {
        registry_source(path): module_declarations(
            path, sources[relative_source(path)]
        )
        for path in declaration_sources
    }
    main = sources["src/main.rs"]
    manifest = MANIFEST_PATH.read_text(encoding="utf-8")
    unsafe_files = {
        row["source"]: row["unsafe_blocks"]
        for row in rows
        if row["unsafe_blocks"]
    }
    libc_calls = sorted(
        set(
            re.findall(
                r"libc::([A-Za-z_][A-Za-z0-9_]*)",
                "\n".join(
                    sources[(REPO_ROOT / source).relative_to(CRATE_ROOT).as_posix()]
                    for source in unsafe_files
                ),
            )
        )
    )
    return {
        "schema_version": 1,
        "generated": "2026-08-23",
        "crate": "dcentrald",
        "crate_root": registry_source(CRATE_ROOT / "src/main.rs"),
        "authority_ceiling": AUTHORITY_CEILING,
        "ledger_rows": [],
        "ledger_scope_reason": LEDGER_SCOPE_REASON,
        "package": {
            "name": toml_string(toml_section(manifest, "package"), "name"),
            "description": toml_string(
                toml_section(manifest, "package"), "description"
            ),
            "license": toml_string(toml_section(manifest, "package"), "license"),
            "binaries": manifest_binaries(manifest),
            "dependencies": toml_keys(toml_section(manifest, "dependencies")),
            "dev_dependencies": toml_keys(
                toml_section(manifest, "dev-dependencies")
            ),
            "features": toml_string_array_map(toml_section(manifest, "features")),
            "clippy_lints": toml_string_map(
                toml_section(manifest, "lints.clippy")
            ),
            "workspace_member": True,
            "default_workspace_member": True,
        },
        "module_declarations": declarations,
        "modules": rows,
        "source_totals": {
            "rust_files": len(rows),
            "bytes": sum(int(row["bytes"]) for row in rows),
            "unit_test_attributes": sum(
                int(row["test_attributes"]) for row in rows
            ),
            "unsafe_blocks": sum(int(row["unsafe_blocks"]) for row in rows),
            "visible_items": sum(int(row["visible_items"]) for row in rows),
            "tree_sha256": source_tree_sha256(files, raw_by_source),
        },
        "cli_surface": {
            "boolean_flags": rust_string_array(main, "KNOWN_CLI_BOOL_FLAGS"),
            "value_flags": rust_string_array(main, "KNOWN_CLI_VALUE_FLAGS"),
            "unknown_flag_exit": 2,
            "help_precedes_hardware": True,
        },
        "runtime_dispatch_kinds": [
            "Bm1396Native",
            "Bm1391Native",
            "C43Native",
            "Am3BeagleBone",
            "StratumProxy",
            "Tap",
            "S19jHybrid",
            "S17Hybrid",
            "Serial",
            "StockFpga",
            "StandardDaemon",
        ],
        "action_surfaces": ACTION_SURFACES,
        "feature_profiles": FEATURE_PROFILES,
        "integration_tests": integration,
        "fixtures": fixtures,
        "test_totals": {
            "unit_test_attributes": sum(
                int(row["test_attributes"]) for row in rows
            ),
            "integration_files": len(integration),
            "integration_test_attributes": sum(
                int(row["test_attributes"]) for row in integration
            ),
            "total_test_attributes": sum(
                int(row["test_attributes"]) for row in rows + integration
            ),
        },
        "lexical_effect_file_census": {
            category: sorted(
                registry_source(path)
                for path in files
                if pattern.search(sources[relative_source(path)])
            )
            for category, pattern in EFFECT_PATTERNS.items()
        },
        "unsafe_surface": {
            "files": unsafe_files,
            "libc_identifiers": libc_calls,
            "unsafe_op_in_unsafe_fn": "deny",
            "discovery_unsafe_code": "forbid",
        },
        "wave512_hardening_tests": [
            "config_load_is_bounded_regular_file_only_and_absence_is_exact",
            "config_load_refuses_valid_and_dangling_symlinks_without_fallback_authority",
        ],
        "artifact_consumers": ARTIFACT_CONSUMERS,
        "init_consumers": INIT_CONSUMERS,
        "known_external_blockers": KNOWN_EXTERNAL_BLOCKERS,
    }


class DcentraldDaemonSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.actual = build_registry()
        cls.main = (SOURCE_ROOT / "main.rs").read_text(encoding="utf-8")
        cls.config = (SOURCE_ROOT / "config.rs").read_text(encoding="utf-8")
        cls.discovery = (SOURCE_ROOT / "bin/dcentos_discovery.rs").read_text(
            encoding="utf-8"
        )

    def test_registry_identity_and_authority_ceiling(self) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald")
        self.assertEqual(self.registry["ledger_rows"], [])
        self.assertGreaterEqual(len(self.registry["authority_ceiling"]), 400)
        self.assertGreaterEqual(len(self.registry["ledger_scope_reason"]), 220)
        self.assertEqual(self.registry["action_surfaces"], ACTION_SURFACES)

    def test_manifest_binaries_dependencies_features_and_workspace_are_exact(self) -> None:
        self.assertEqual(self.registry["package"], self.actual["package"])
        features = self.registry["package"]["features"]
        profiles = {row["profile"]: row for row in self.registry["feature_profiles"]}
        self.assertEqual(set(profiles), set(features) | {"all-features"})
        self.assertEqual(profiles["all-features"]["features"], sorted(set(features) - {"default"}))
        self.assertEqual(features["default"], [])
        self.assertNotIn("recovery-tool", features)
        workspace = toml_section(
            WORKSPACE_MANIFEST_PATH.read_text(encoding="utf-8"), "workspace"
        )
        self.assertIn("dcentrald", toml_string_array(workspace, "members"))
        self.assertIn("dcentrald", toml_string_array(workspace, "default-members"))
        self.assertFalse((SOURCE_ROOT / "lib.rs").exists())

    def test_complete_module_declaration_census_and_tree_are_exact(self) -> None:
        self.assertEqual(self.registry["module_declarations"], self.actual["module_declarations"])
        self.assertEqual(self.registry["modules"], self.actual["modules"])
        self.assertEqual(self.registry["source_totals"], self.actual["source_totals"])

    def test_cli_and_runtime_dispatch_vocabularies_are_exact(self) -> None:
        self.assertEqual(self.registry["cli_surface"], self.actual["cli_surface"])
        dispatch = self.main[
            self.main.index("enum RuntimeDispatchKind") : self.main.index(
                "impl RuntimeDispatchKind"
            )
        ]
        variants = re.findall(r"^\s{4}([A-Za-z0-9_]+),$", dispatch, re.M)
        self.assertEqual(variants, self.registry["runtime_dispatch_kinds"])
        run_main = self.main[self.main.index("async fn run_main(") :]
        self.assertLess(
            run_main.index("wants_cli_info(&args)"),
            run_main.index("run_set_fan_oneshot(pwm_arg"),
        )

    def test_integration_sources_fixtures_and_test_totals_are_exact(self) -> None:
        self.assertEqual(self.registry["integration_tests"], self.actual["integration_tests"])
        self.assertEqual(self.registry["fixtures"], self.actual["fixtures"])
        self.assertEqual(self.registry["test_totals"], self.actual["test_totals"])

    def test_conservative_effect_and_unsafe_censuses_are_exact(self) -> None:
        self.assertEqual(
            self.registry["lexical_effect_file_census"],
            self.actual["lexical_effect_file_census"],
        )
        self.assertEqual(self.registry["unsafe_surface"], self.actual["unsafe_surface"])
        self.assertIn("#![deny(unsafe_op_in_unsafe_fn)]", self.main)
        self.assertIn("#![forbid(unsafe_code)]", self.discovery)
        # Lexical census includes exact private host-test sources; this does
        # not execute those blocks or confer hardware/production admission.
        self.assertEqual(self.registry["source_totals"]["unsafe_blocks"], 89)
        self.assertEqual(
            self.registry["unsafe_surface"]["files"],
            {
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/am3_bb_mining.rs": 9,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/am3_bb_pre_power_run_tests.rs": 3,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/fpga.rs": 2,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/s19k_endurance.rs": 6,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs": 58,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining/classic_aml_proof.rs": 1,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining/classic_aml_runtime.rs": 4,
                "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining/modern_native_population_tests.rs": 6,
            },
        )

    def test_config_load_and_fallback_hardening_is_wired(self) -> None:
        for token in [
            "std::fs::symlink_metadata(path)",
            "libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK",
            "file.take((MAX_PERSISTED_CONFIG_BYTES + 1) as u64)",
            "opened config object is not a regular file",
            "fn load_error_is_definitely_absent",
            "if !load_error_is_definitely_absent(&primary_err)",
        ]:
            self.assertIn(token, self.config + self.main)
        self.assertNotIn("std::path::Path::new(&config_path).exists()", self.main)
        for name in self.registry["wave512_hardening_tests"]:
            self.assertIn(f"fn {name}(", self.config)

    def test_discovery_boundary_is_read_only_and_network_explicit(self) -> None:
        for token in [
            "const BITMAIN_PORT: u16 = 14235;",
            "const DCENT_PORT: u16 = 14237;",
            "const MDNS_PORT: u16 = 5353;",
            "UdpSocket::bind",
            "poll_ip_reporter_requests",
            "ButtonWatcher",
        ]:
            self.assertIn(token, self.discovery)
        for forbidden in ["Command::new", "reqwest", "std::fs::write", "reboot("]:
            self.assertNotIn(forbidden, self.discovery)

    def test_artifact_init_ci_and_campaign_ownership_are_exact(self) -> None:
        self.assertEqual(self.registry["artifact_consumers"], ARTIFACT_CONSUMERS)
        self.assertEqual(self.registry["init_consumers"], INIT_CONSUMERS)
        for binary, paths in ARTIFACT_CONSUMERS.items():
            for relative in paths:
                text = (DCENTOS_ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(binary, text)
        for relative in INIT_CONSUMERS:
            self.assertIn("dcentrald", (DCENTOS_ROOT / relative).read_text(encoding="utf-8"))
        workflow = (REPO_ROOT / ".github/workflows/dcentos-offline-gates.yml").read_text(encoding="utf-8")
        aggregate = (DCENTOS_ROOT / "scripts/ci_offline_gates.sh").read_text(encoding="utf-8")
        campaign = (REPO_ROOT / "").read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentrald --bins --tests --no-fail-fast", workflow)
        self.assertIn("test_dcentrald_daemon_surface_registry.py", aggregate)
        self.assertIn("Root daemon convergence", campaign)

    def test_external_blockers_and_non_execution_posture_are_explicit(self) -> None:
        self.assertEqual(self.registry["feature_profiles"], FEATURE_PROFILES)
        self.assertEqual(self.registry["known_external_blockers"], KNOWN_EXTERNAL_BLOCKERS)
        self.assertGreaterEqual(len(KNOWN_EXTERNAL_BLOCKERS), 12)
        self.assertTrue(all(len(item) >= 120 for item in KNOWN_EXTERNAL_BLOCKERS))


if __name__ == "__main__":
    if sys.argv[1:] == ["--update"]:
        REGISTRY_PATH.write_bytes(
            (json.dumps(build_registry(), indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        )
    else:
        unittest.main()
