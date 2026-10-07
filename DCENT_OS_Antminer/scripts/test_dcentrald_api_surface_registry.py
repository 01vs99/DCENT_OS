#!/usr/bin/env python3
"""Pin the complete source-level dcentrald-api authority surface."""

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
CRATE_ROOT = WORKSPACE_ROOT / "dcentrald-api"
SOURCE_ROOT = CRATE_ROOT / "src"
TEST_ROOT = CRATE_ROOT / "tests"
MANIFEST_PATH = CRATE_ROOT / "Cargo.toml"
WORKSPACE_MANIFEST_PATH = WORKSPACE_ROOT / "Cargo.toml"
REGISTRY_PATH = (
    DCENTOS_ROOT
    / "docs"
    / "architecture"
    / "dcentrald_api_surface_registry.json"
)

LAB_FEATURE_PROFILE = {
    "profile": "lab",
    "features": ["lab"],
    "authority": "Compile-time laboratory hardware readers forward to the common capability; signed Beta/Stable runtime admission refuses this feature union, and it grants no independent hardware ownership.",
}

TEST_ATTRIBUTE_RE = re.compile(
    r"^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]", re.MULTILINE
)
PUBLIC_FUNCTION_RE = re.compile(
    r"^\s*pub\s+(?:async\s+|const\s+|unsafe\s+)*fn\s+[A-Za-z0-9_]+",
    re.MULTILINE,
)
PUBLIC_ITEM_RE = re.compile(
    r"^\s*pub\s+(?:struct|enum|trait|type|const|static)\s+[A-Za-z0-9_]+",
    re.MULTILINE,
)
ROUTE_RE = re.compile(r"(?s)(?<![\"'])\.route\(\s*\"([^\"]+)\"")
TEST_ONLY_ROUTES = {
    "/bare-text",
    "/binary",
    "/json-object",
    "/json-string",
    "/legacy-error",
    "/ok",
}

EFFECT_PATTERNS = {
    "network": re.compile(
        r"TcpListener|TcpStream|UdpSocket|UnixListener|connect_async|rumqttc|reqwest",
        re.IGNORECASE,
    ),
    "process": re.compile(
        r"Command::|std::process|tokio::process", re.IGNORECASE
    ),
    "filesystem": re.compile(
        r"std::fs|tokio::fs|OpenOptions|File::|read_to_string|write\(",
        re.IGNORECASE,
    ),
    "ffi": re.compile(r"libc::|extern\s+\"C\"", re.IGNORECASE),
    "device": re.compile(
        r"/dev/|sysfs|/sys/|/proc/|gpio|i2c|uart|mmio", re.IGNORECASE
    ),
    "reboot": re.compile(
        r"reboot|sysrq|poweroff|shutdown", re.IGNORECASE
    ),
}


def relative_source(path: Path) -> str:
    return path.relative_to(CRATE_ROOT).as_posix()


def registry_source(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def source_files() -> list[Path]:
    return sorted(SOURCE_ROOT.rglob("*.rs"), key=relative_source)


def module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT)
    if relative == Path("lib.rs"):
        return "crate_root"
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
    match = re.search(
        rf"(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)", text
    )
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
    match = re.search(
        rf"(?ms)^{re.escape(key)}\s*=\s*\[(.*?)^\]", text
    )
    if match is None:
        raise AssertionError(f"missing TOML array {key}")
    return re.findall(r'"([^\"]+)"', match.group(1))


def toml_string_array_map(section: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for match in re.finditer(
        r"(?m)^([A-Za-z0-9_-]+)\s*=\s*(\[[^\r\n]*\])", section
    ):
        result[match.group(1)] = json.loads(match.group(2))
    return result


def toml_string_map(section: str) -> dict[str, str]:
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'(?m)^([A-Za-z0-9_-]+)\s*=\s*"([^\"]*)"', section
        )
    }


def source_metrics(path: Path, raw: bytes) -> dict[str, object]:
    text = raw.decode()
    return {
        "module": module_name(path),
        "source": registry_source(path),
        "bytes": len(raw),
        "test_attributes": len(TEST_ATTRIBUTE_RE.findall(text)),
        "unsafe_blocks": len(re.findall(r"\bunsafe\s*\{", text)),
        "public_items": len(PUBLIC_FUNCTION_RE.findall(text))
        + len(PUBLIC_ITEM_RE.findall(text)),
    }


def integration_metrics(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    text = raw.decode()
    return {
        "source": registry_source(path),
        "bytes": len(raw),
        "test_attributes": len(TEST_ATTRIBUTE_RE.findall(text)),
        "sha256": sha256_bytes(raw),
    }


def fixture_metrics(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "source": registry_source(path),
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
    }


def route_family(path: str) -> str:
    if path in {"/", "/ws", "/mcp", "/metrics"}:
        return path
    match = re.match(r"^/api/([^/]+)", path)
    if match:
        return f"/api/{match.group(1)}"
    return "other"


class DcentraldApiSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.files = source_files()
        cls.source_bytes = {
            relative_source(path): path.read_bytes() for path in cls.files
        }
        cls.sources = {
            source: raw.decode() for source, raw in cls.source_bytes.items()
        }
        cls.lib = cls.sources["src/lib.rs"]
        cls.auth = cls.sources["src/auth.rs"]
        cls.cgminer = cls.sources["src/cgminer.rs"]
        cls.luxos = cls.sources["src/cgminer_luxos.rs"]

    def test_registry_identity_and_authority_ceiling(self) -> None:
        self.assertEqual(self.registry["schema_version"], 1)
        self.assertEqual(self.registry["crate"], "dcentrald-api")
        self.assertEqual(
            self.registry["crate_root"],
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/lib.rs",
        )
        self.assertEqual(self.registry["ledger_rows"], [])
        self.assertGreaterEqual(len(self.registry["authority_ceiling"]), 300)
        self.assertGreaterEqual(len(self.registry["ledger_scope_reason"]), 180)

    def test_manifest_features_dependencies_and_workspace_scope_are_exact(self) -> None:
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")
        package = toml_section(manifest, "package")
        expected = self.registry["package"]
        self.assertEqual(toml_string(package, "name"), expected["name"])
        self.assertEqual(
            toml_string(package, "description"), expected["description"]
        )
        self.assertEqual(toml_string(package, "license"), expected["license"])
        self.assertEqual(
            toml_keys(toml_section(manifest, "dependencies")),
            expected["dependencies"],
        )
        self.assertEqual(
            toml_keys(toml_section(manifest, "dev-dependencies")),
            expected["dev_dependencies"],
        )
        self.assertEqual(
            toml_string_array_map(toml_section(manifest, "features")),
            expected["features"],
        )
        profiles = {row["profile"]: row for row in self.registry["feature_profiles"]}
        self.assertEqual(set(profiles), set(expected["features"]) | {"default"})
        self.assertEqual(profiles["lab"], LAB_FEATURE_PROFILE)
        self.assertIn("dcentrald-common/lab", expected["features"]["lab"])
        self.assertEqual(expected["features"]["recovery-tool"], ["dcentrald-common/lab"])
        self.assertEqual(
            toml_string_map(toml_section(manifest, "lints.clippy")),
            expected["clippy_lints"],
        )

        workspace = toml_section(
            WORKSPACE_MANIFEST_PATH.read_text(encoding="utf-8"), "workspace"
        )
        self.assertIn("dcentrald-api", toml_string_array(workspace, "members"))
        self.assertIn(
            "dcentrald-api", toml_string_array(workspace, "default-members")
        )

    def test_complete_module_census_and_source_tree_are_exact(self) -> None:
        actual = [
            source_metrics(path, self.source_bytes[relative_source(path)])
            for path in self.files
        ]
        self.assertEqual(actual, self.registry["modules"])
        totals = self.registry["source_totals"]
        self.assertEqual(len(actual), totals["rust_files"])
        self.assertEqual(sum(row["bytes"] for row in actual), totals["bytes"])
        self.assertEqual(
            sum(row["test_attributes"] for row in actual),
            totals["unit_test_attributes"],
        )
        self.assertEqual(
            sum(row["unsafe_blocks"] for row in actual), totals["unsafe_blocks"]
        )
        self.assertEqual(
            sum(row["public_items"] for row in actual), totals["public_items"]
        )
        self.assertEqual(
            source_tree_sha256(self.files, self.source_bytes), totals["tree_sha256"]
        )

        root_modules = sorted(re.findall(r"^pub mod ([A-Za-z0-9_]+);", self.lib, re.M))
        route_modules = sorted(
            re.findall(
                r"^pub mod ([A-Za-z0-9_]+);", self.sources["src/routes/mod.rs"], re.M
            )
        )
        self.assertEqual(root_modules, self.registry["root_public_modules"])
        self.assertEqual(route_modules, self.registry["route_public_modules"])

    def test_literal_route_surface_and_family_counts_are_exact(self) -> None:
        all_routes: list[str] = []
        for text in self.sources.values():
            all_routes.extend(ROUTE_RE.findall(text))
        self.assertEqual(len(all_routes), len(set(all_routes)))
        self.assertEqual(set(all_routes) & TEST_ONLY_ROUTES, TEST_ONLY_ROUTES)
        production = sorted(set(all_routes) - TEST_ONLY_ROUTES)
        route_registry = self.registry["literal_route_surface"]
        self.assertEqual(len(production), route_registry["production_routes"])
        self.assertEqual(
            sha256_bytes("\n".join(production).encode()),
            route_registry["canonical_path_sha256"],
        )
        families: dict[str, int] = {}
        for path in production:
            family = route_family(path)
            families[family] = families.get(family, 0) + 1
        self.assertEqual(dict(sorted(families.items())), route_registry["families"])
        self.assertEqual(
            sorted(TEST_ONLY_ROUTES), route_registry["test_only_routes"]
        )

    def test_cgminer_and_luxos_command_vocabularies_are_exact(self) -> None:
        legacy_block = self.cgminer[
            self.cgminer.index("match cmd.command.as_str() {") : self.cgminer.index(
                "other if crate::cgminer_luxos::is_luxos_command"
            )
        ]
        legacy = sorted(set(re.findall(r'"([a-z][a-z0-9_]*)"', legacy_block)))
        luxos_block = self.luxos[
            self.luxos.index("pub fn is_luxos_command") : self.luxos.index(
                "fn luxos_command_for"
            )
        ]
        luxos = sorted(set(re.findall(r'"([a-z][a-z0-9_]*)"', luxos_block)))
        self.assertEqual(legacy, self.registry["cgminer_surface"]["legacy_dispatch"])
        self.assertEqual(luxos, self.registry["cgminer_surface"]["luxos_dispatch"])
        self.assertTrue(set(legacy).isdisjoint(luxos))

    def test_integration_suites_and_binary_fixtures_are_exact(self) -> None:
        integration = [
            integration_metrics(path) for path in sorted(TEST_ROOT.glob("*.rs"))
        ]
        fixtures = [
            fixture_metrics(path)
            for path in sorted(path for path in TEST_ROOT.rglob("*") if path.is_file() and path.suffix != ".rs")
        ]
        self.assertEqual(integration, self.registry["integration_tests"])
        self.assertEqual(fixtures, self.registry["fixtures"])
        totals = self.registry["test_totals"]
        self.assertEqual(len(integration), totals["integration_files"])
        self.assertEqual(
            sum(row["test_attributes"] for row in integration),
            totals["integration_test_attributes"],
        )
        self.assertEqual(
            totals["unit_test_attributes"] + totals["integration_test_attributes"],
            totals["total_test_attributes"],
        )

    def test_conservative_effect_file_census_is_exact(self) -> None:
        actual: dict[str, list[str]] = {}
        for category, pattern in EFFECT_PATTERNS.items():
            actual[category] = sorted(
                registry_source(path)
                for path in self.files
                if pattern.search(self.sources[relative_source(path)])
            )
        self.assertEqual(actual, self.registry["lexical_effect_file_census"])

    def test_unsafe_surface_keeps_statvfs_and_exact_ssh_owner_boundaries(self) -> None:
        actual = {
            registry_source(path): len(
                re.findall(r"\bunsafe\s*\{", self.sources[relative_source(path)])
            )
            for path in self.files
            for text in [self.sources[relative_source(path)]]
            if re.search(r"\bunsafe\s*\{", text)
        }
        self.assertEqual(actual, self.registry["unsafe_surface"]["files"])
        self.assertEqual(actual, {
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/channel_download.rs": 4,
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/diagnostics.rs": 1,
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/rest/late.rs": 2,
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/routes/restore_to_stock.rs": 2,
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/routes/ssh_keys.rs": 9,
            "DCENT_OS_Antminer/dcentrald/dcentrald-api/src/routes/ssh_keys_tests.rs": 1,
        })
        self.assertNotRegex(
            "\n".join(self.sources.values()), r"\b(?:pub\s+)?unsafe\s+fn\b"
        )
        self.assertIn("#![deny(unsafe_op_in_unsafe_fn)]", self.lib)
        for source in ("src/rest/late.rs", "src/routes/restore_to_stock.rs"):
            text = self.sources[source]
            self.assertEqual(text.count("unsafe { libc::statvfs"), 1)
            self.assertEqual(text.count("unsafe { stat.assume_init() }"), 1)
        # These new read-only libc boundaries observe the process owner and
        # available filesystem space; neither grants mutation authority.
        download = self.sources["src/channel_download.rs"]
        self.assertEqual(download.count("unsafe { libc::geteuid() }"), 2)
        self.assertEqual(download.count("unsafe { libc::statvfs("), 1)
        self.assertEqual(download.count("unsafe { info.assume_init() }"), 1)
        self.assertEqual(self.sources["src/diagnostics.rs"].count("unsafe { libc::geteuid() }"), 1)
        ssh = self.sources["src/routes/ssh_keys.rs"]
        # Exact existing descriptor-owner implementation; no generic unsafe
        # exemption and no additional filesystem or hardware authority.
        for call, count in {
            "libc::openat(": 1, "File::from_raw_fd(": 1,
            "libc::fstatat(": 2, "libc::readlinkat(": 1,
            "libc::unlinkat(": 1, "libc::renameat(": 1,
        }.items():
            self.assertEqual(ssh.count(call), count, call)
        for token in ("libc::O_NOFOLLOW", "libc::O_CLOEXEC", "libc::AT_SYMLINK_NOFOLLOW"):
            self.assertIn(token, ssh)
        self.assertIn('#[cfg(test)]\n#[path = "ssh_keys_tests.rs"]\nmod tests;', ssh)
        self.assertIn(
            "unsafe { libc::mkfifo(name.as_ptr(), 0o600) }",
            self.sources["src/routes/ssh_keys_tests.rs"],
        )

    def test_wave511_auth_cors_and_persistence_hardening_is_wired(self) -> None:
        for token in [
            "MAX_AUTH_FILE_BYTES",
            "libc::O_NOFOLLOW | libc::O_CLOEXEC",
            "file.take(MAX_AUTH_FILE_BYTES.saturating_add(1))",
            "return release_image.then(corrupt_auth_sentinel);",
            "auth path must be an exact regular file",
            "auth parent path must be an exact directory",
        ]:
            self.assertIn(token, self.auth)
        self.assertIn("fn parsed_http_origin_authority", self.lib)
        self.assertIn("fn cors_origin_is_allowed", self.lib)
        self.assertNotIn('origin_str.starts_with("http://localhost")', self.lib)
        self.assertIn("fn admit_auth_storage_before_bind", self.lib)
        admission = self.lib.index("admit_auth_storage_before_bind(")
        first_bind = self.lib.index("TcpListener::bind")
        self.assertLess(admission, first_bind)

        led_start = self.lib.index("pub fn update_led_config")
        led_end = self.lib.index("#[cfg(test)]", led_start)
        led = self.lib[led_start:led_end]
        self.assertIn("atomic_io::config_write_lock()", led)
        self.assertIn("atomic_io::atomic_write(path, output)", led)
        self.assertNotIn("std::fs::write", led)
        for test_name in self.registry["wave511_hardening_tests"]:
            self.assertIn(f"fn {test_name}(", self.lib + self.auth)

    def test_direct_consumers_ci_and_non_execution_posture_are_pinned(self) -> None:
        consumers: list[str] = []
        # Every crate and the nested cargo-fuzz workspace is one directory
        # below WORKSPACE_ROOT. Do not recurse through Cargo's enormous
        # ignored target/ tree on mounted workspaces.
        for manifest_path in sorted(WORKSPACE_ROOT.glob("*/Cargo.toml")):
            if manifest_path == MANIFEST_PATH:
                continue
            manifest = manifest_path.read_text(encoding="utf-8")
            dependencies = re.search(r"(?m)^\[dependencies\]\s*$", manifest)
            if dependencies is None:
                continue
            if "dcentrald-api" in toml_keys(toml_section(manifest, "dependencies")):
                consumers.append(toml_string(toml_section(manifest, "package"), "name"))
        self.assertEqual(consumers, self.registry["direct_consumers"])

        workflow = (
            REPO_ROOT / ".github/workflows/dcentrald-api-tests.yml"
        ).read_text(encoding="utf-8")
        aggregate = (DCENTOS_ROOT / "scripts/ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("cargo +1.90.0 test --locked -p dcentrald-api --tests --no-fail-fast", workflow)
        self.assertIn("test_dcentrald_api_surface_registry.py", aggregate)
        self.assertGreaterEqual(len(self.registry["known_external_blockers"]), 10)
        self.assertTrue(
            all(len(item) >= 90 for item in self.registry["known_external_blockers"])
        )


def update_source_snapshot() -> None:
    """Refresh only the mechanically derived source census in the registry."""

    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    manifest = MANIFEST_PATH.read_text(encoding="utf-8")
    registry["package"]["features"] = toml_string_array_map(toml_section(manifest, "features"))
    registry["package"]["dependencies"] = toml_keys(toml_section(manifest, "dependencies"))
    registry["feature_profiles"] = [
        row for row in registry["feature_profiles"] if row["profile"] != "lab"
    ] + [LAB_FEATURE_PROFILE]
    files = source_files()
    source_bytes = {relative_source(path): path.read_bytes() for path in files}
    modules = [
        source_metrics(path, source_bytes[relative_source(path)]) for path in files
    ]
    registry["modules"] = modules
    registry["source_totals"] = {
        "rust_files": len(modules),
        "bytes": sum(int(row["bytes"]) for row in modules),
        "unit_test_attributes": sum(
            int(row["test_attributes"]) for row in modules
        ),
        "unsafe_blocks": sum(int(row["unsafe_blocks"]) for row in modules),
        "public_items": sum(int(row["public_items"]) for row in modules),
        "tree_sha256": source_tree_sha256(files, source_bytes),
    }
    texts = {source: raw.decode("utf-8") for source, raw in source_bytes.items()}
    registry["root_public_modules"] = sorted(
        re.findall(r"^pub mod ([A-Za-z0-9_]+);", texts["src/lib.rs"], re.M)
    )
    registry["route_public_modules"] = sorted(
        re.findall(r"^pub mod ([A-Za-z0-9_]+);", texts["src/routes/mod.rs"], re.M)
    )
    routes = sorted({route for text in texts.values() for route in ROUTE_RE.findall(text)} - TEST_ONLY_ROUTES)
    families: dict[str, int] = {}
    for route in routes:
        family = route_family(route)
        families[family] = families.get(family, 0) + 1
    registry["literal_route_surface"].update({
        "production_routes": len(routes),
        "canonical_path_sha256": sha256_bytes("\n".join(routes).encode()),
        "families": dict(sorted(families.items())),
    })
    registry["lexical_effect_file_census"] = {
        category: sorted(registry_source(path) for path in files
                         if pattern.search(texts[relative_source(path)]))
        for category, pattern in EFFECT_PATTERNS.items()
    }
    registry["unsafe_surface"]["files"] = {
        registry_source(path): len(re.findall(r"\bunsafe\s*\{", texts[relative_source(path)]))
        for path in files if re.search(r"\bunsafe\s*\{", texts[relative_source(path)])
    }
    registry["unsafe_surface"]["call_family"] = (
        "Three checked statvfs wrappers and three pointer-free geteuid observations; "
        "exact retained-directory SSH-key openat/"
        "fstatat/readlinkat/renameat/unlinkat and descriptor ownership; one "
        "private cfg(test) mkfifo refusal fixture. Lexical inventory is not execution."
    )
    registry["test_totals"]["unit_test_attributes"] = registry["source_totals"]["unit_test_attributes"]
    registry["test_totals"]["total_test_attributes"] = (
        registry["test_totals"]["unit_test_attributes"]
        + registry["test_totals"]["integration_test_attributes"]
    )
    REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
        newline="\n",
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--update"]:
        update_source_snapshot()
    else:
        unittest.main()
