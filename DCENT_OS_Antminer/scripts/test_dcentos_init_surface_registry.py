#!/usr/bin/env python3
"""Pin dcentos-init's complete PID-1 authority and host-test boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
DCENTOS_ROOT = REPO_ROOT / "projects" / "dcentos"
CRATE_ROOT = DCENTOS_ROOT / "dcentrald" / "dcentos-init"
SOURCE_PATH = CRATE_ROOT / "src" / "main.rs"
REGISTRY_PATH = (
    DCENTOS_ROOT / "docs" / "architecture" / "dcentos_init_surface_registry.json"
)

EXPECTED_FIXED_POLICY = {
    "console_device": "/dev/console",
    "early_init": "/etc/dcentos-early-init.sh",
    "external_media_marker": "/etc/dcentos/external-media-ephemeral-root",
    "external_media_services": [
        "S45persistent",
        "S01syslogd",
        "S02klogd",
        "S40network",
        "S41ntp",
        "S43logrotate",
        "S50dropbear",
    ],
    "getty_baud": "115200",
    "getty_tty": "ttyPS0",
    "init_directory": "/etc/init.d",
    "shutdown_watchdog_ms": 60_000,
}

EXPECTED_FUNCTION_GROUPS = {
    "boot_filesystem_and_device": [
        "do_mount",
        "ensure_console",
        "fallback_early_init",
        "mount_virtual_fs",
    ],
    "console_and_process": [
        "console_profile",
        "find_shell",
        "fork_exec",
        "fork_exec_with_tty",
        "getty_args",
        "getty_is_busybox",
        "getty_is_busybox_with_candidates",
        "is_executable",
        "spawn_getty",
    ],
    "external_media_and_service_policy": [
        "execute_init_scripts",
        "external_media_marker_state",
        "is_exact_executable_regular_file",
        "run_early_init",
        "run_init_scripts",
        "run_init_scripts_from",
        "select_and_order_scripts",
        "service_posture",
    ],
    "lifecycle_entry": ["main"],
    "signal_and_process_control": [
        "alarm_handler",
        "install_one_handler",
        "install_signal_handlers",
        "signal_handler",
    ],
    "shutdown_and_kernel_control": [
        "arm_emergency_watchdog",
        "do_shutdown",
        "emergency_kernel_action",
        "external_shutdown_scripts",
        "shutdown_action_for_signal",
        "unmount_all",
        "write_kernel_control_byte",
    ],
    "time_and_deadline": [
        "add_millis_to_timespec",
        "monotonic_deadline_after",
        "relative_sleep_ms",
        "retry_absolute_wait",
        "sleep_ms",
        "sleep_until_monotonic",
    ],
}

EXPECTED_TESTS = {
    "exact_bm1362_aml_uses_kernel_console_without_naming_an_asic_uart",
    "absolute_deadline_wait_retries_every_eintr",
    "console_only_posture_admits_no_start_or_stop_scripts",
    "emergency_path_has_no_blocking_userspace_work_before_reboot",
    "external_early_init_failure_and_unsafe_marker_are_console_only",
    "external_media_service_set_is_exact_and_shutdown_is_its_reverse",
    "external_missing_readiness_gate_refuses_the_whole_pass",
    "external_nonexecutable_readiness_gate_refuses_the_whole_pass",
    "external_nonzero_readiness_gate_bars_every_later_service",
    "optional_external_failure_retains_network_but_never_starts_mining",
    "external_readiness_gate_runs_first_before_remaining_services",
    "external_shutdown_is_limited_to_successfully_admitted_services",
    "external_symlink_readiness_gate_refuses_the_whole_pass",
    "getty_args_agetty_order_is_tty_then_baud",
    "getty_args_busybox_order_is_baud_then_tty",
    "getty_args_orders_are_mutually_distinct",
    "getty_busybox_classifier_recognizes_hard_link_identity",
    "getty_is_busybox_false_for_nonexistent_path",
    "marker_must_be_an_exact_empty_regular_file",
    "marker_symlink_is_unsafe_even_when_target_is_empty",
    "monotonic_deadline_arithmetic_normalizes_nanosecond_carry",
    "select_and_order_scripts_includes_short_and_orders_numerically",
    "shutdown_runs_service_teardown_before_global_kill_sweep",
    "shutdown_watchdog_exceeds_daemon_typed_teardown_budget",
    "sigint_reboots",
    "sigterm_reboots",
    "sigusr1_halts",
    "sigusr2_powers_off_not_reboots",
    "unknown_signal_defaults_to_reboot",
}

EXPECTED_LIBC_CALLS = {
    "_exit",
    "access",
    "alarm",
    "clock_gettime",
    "clock_nanosleep",
    "close",
    "dup2",
    "execvp",
    "fork",
    "getpid",
    "ioctl",
    "kill",
    "makedev",
    "mknod",
    "mount",
    "nanosleep",
    "open",
    "pause",
    "reboot",
    "sethostname",
    "setsid",
    "sigaction",
    "sigemptyset",
    "signal",
    "sync",
    "umount2",
    "waitpid",
    "write",
}

EXPECTED_ARTIFACT_CONSUMERS = [
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19jpro-aml/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21pro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s21xp/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-t21/post-build.sh",
    # 2026-08-27 armada (C1): B2 shipped the three 17-series sibling board
    # dirs; their post-build.sh scripts stamp the same staged dcentrald
    # artifact consumer surface as am2-s17pro. (List stays generator-sorted.)
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17plus/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s17pro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19jpro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-s19pro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/am2-t17plus/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/post-build.sh",
]

ACTION_SURFACES = [
    {
        "surface": "pid1_and_signal_ownership",
        "functions": ["main", "install_signal_handlers", "install_one_handler"],
        "authority": "Requires PID 1 and installs process-global signal disposition before boot mutation.",
    },
    {
        "surface": "filesystem_and_device_bootstrap",
        "functions": ["ensure_console", "mount_virtual_fs", "fallback_early_init", "do_mount"],
        "authority": "Can mount procfs/sysfs/tmpfs/devpts, create device nodes including /dev/mem, create directories/symlinks, and set the hostname.",
    },
    {
        "surface": "root_script_execution",
        "functions": ["run_early_init", "run_init_scripts_from", "execute_init_scripts"],
        "authority": "Executes image-owned early-init and SysV scripts as root; normal and external-media admission policies are distinct.",
    },
    {
        "surface": "recovery_console",
        "functions": ["spawn_getty", "fork_exec", "fork_exec_with_tty"],
        "authority": "Forks and execs login/getty/shell processes and can expose the intentional passwordless physical root recovery console.",
    },
    {
        "surface": "shutdown_and_process_sweep",
        "functions": ["do_shutdown", "unmount_all"],
        "authority": "Runs root stop scripts, signals all residual processes, syncs, unmounts filesystems, and remounts root read-only.",
    },
    {
        "surface": "terminal_kernel_action",
        "functions": ["arm_emergency_watchdog", "emergency_kernel_action", "write_kernel_control_byte"],
        "authority": "Enables and triggers sysrq and invokes reboot or power-off after an absolute shutdown deadline.",
    },
]


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def dependency_names(manifest: str) -> list[str]:
    match = re.search(r"(?ms)^\[dependencies\]\s*(.*?)(?=^\[|\Z)", manifest)
    if not match:
        return []
    return sorted(
        line.split("=", 1)[0].strip()
        for line in match.group(1).splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    )


def production_source(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


def artifact_consumers() -> list[str]:
    board_root = DCENTOS_ROOT / "br2_external_dcentos" / "board"
    return sorted(
        relative(path)
        for path in board_root.rglob("post-build.sh")
        if "DCENTOS_INIT" in path.read_text(encoding="utf-8")
    )


def fixed_policy(source: str) -> dict[str, object]:
    def string_constant(name: str) -> str:
        match = re.search(rf'^const {name}: &str = "([^"]+)";', source, re.M)
        if not match:
            raise AssertionError(f"missing string constant {name}")
        return match.group(1)

    services_match = re.search(
        r"(?ms)^const EXTERNAL_MEDIA_SERVICES: &\[&str\] = &\[(.*?)^\];",
        source,
    )
    if not services_match:
        raise AssertionError("missing EXTERNAL_MEDIA_SERVICES")
    services = re.findall(r'^\s*"([^"]+)",', services_match.group(1), re.M)
    watchdog_match = re.search(
        r"^const SHUTDOWN_WATCHDOG_MS: u64 = ([0-9_]+);", source, re.M
    )
    if not watchdog_match:
        raise AssertionError("missing SHUTDOWN_WATCHDOG_MS")
    return {
        "console_device": string_constant("CONSOLE_DEV"),
        "early_init": string_constant("EARLY_INIT"),
        "external_media_marker": string_constant("EXTERNAL_MEDIA_MARKER"),
        "external_media_services": services,
        "getty_baud": string_constant("GETTY_BAUD"),
        "getty_tty": string_constant("GETTY_TTY"),
        "init_directory": string_constant("INIT_D"),
        "shutdown_watchdog_ms": int(watchdog_match.group(1).replace("_", "")),
    }


def build_registry() -> dict[str, object]:
    source_bytes = SOURCE_PATH.read_bytes()
    source = source_bytes.decode("utf-8")
    production = production_source(source)
    manifest = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    functions = sorted(
        re.findall(r'^(?:extern "C" )?fn ([A-Za-z0-9_]+)', production, re.M)
    )
    tests = sorted(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source))
    libc_calls = sorted(set(re.findall(r"libc::([A-Za-z0-9_]+)\s*\(", production)))
    return {
        "schema_version": 1,
        "generated": "2026-08-20",
        "crate": "dcentos-init",
        "crate_root": relative(SOURCE_PATH),
        "source_bytes": len(source_bytes),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "binary_kind": "private-surface-pid1",
        "public_items": 0,
        "private_types": {
            "enums": {
                "ExternalMediaMarkerState": ["Absent", "Exact", "Unsafe"],
                "ServicePosture": ["Normal", "ExternalRestricted", "ConsoleOnly"],
            },
            "structs": {
                "ServicePassResult": ["succeeded: Vec<String>", "external_gate_admitted: bool"]
            },
            "statics": ["SHUTDOWN_REQUESTED", "SHUTDOWN_SIGNAL"],
            "constants": [
                "CONSOLE_DEV",
                "EARLY_INIT",
                "EXTERNAL_MEDIA_MARKER",
                "EXTERNAL_MEDIA_SERVICES",
                "GETTY_BAUD",
                "GETTY_TTY",
                "INIT_D",
                "SHUTDOWN_WATCHDOG_MS",
            ],
        },
        "private_function_groups": EXPECTED_FUNCTION_GROUPS,
        "private_function_count": len(functions),
        "fixed_policy": fixed_policy(production),
        "action_surfaces": ACTION_SURFACES,
        "unsafe_boundary": {
            "unsafe_blocks": len(re.findall(r"\bunsafe\s*\{", production)),
            "libc_call_census": libc_calls,
            "unsafe_op_in_unsafe_fn": "denied",
            "host_executed": False,
        },
        "compile_profiles": [
            {
                "profile": "default",
                "features": [],
                "unit_tests": len(tests),
                "integration_tests": 0,
                "doc_tests": 0,
                "package_tests": len(tests),
            }
        ],
        "tests": tests,
        "test_boundary": {
            "temporary_shell_fixture_tests": [
                "external_nonzero_readiness_gate_bars_every_later_service",
                "external_readiness_gate_runs_first_before_remaining_services",
            ],
            "production_action_functions_executed": [],
            "device_or_kernel_contact": False,
        },
        "direct_dependencies": dependency_names(manifest),
        "direct_rust_consumers": [],
        "workspace_default_member": True,
        "artifact_consumers": artifact_consumers(),
        "compile_targets": [
            "aarch64-unknown-linux-musl",
            "armv7-unknown-linux-musleabihf",
        ],
        "ledger_rows": [],
        "authority_ceiling": "A compiled PID-1 binary and host tests do not prove target-kernel ABI, boot success, init-script trust, serial-console custody, SafeOff completion, filesystem durability, sysrq availability, reboot/power-off outcome, or any miner hardware state.",
        "known_residuals": [
            "the physical serial recovery console intentionally attempts passwordless root login",
            "normal NAND boot retains a broad image-owned S-prefix script execution policy",
            "script admission is path-based and does not hold an executable descriptor across preflight and shell launch",
            "signal-install, mount, node, process, unmount, sysrq, and reboot syscalls have no live target result proof",
            "the missing-script normal fallback can create privileged device nodes including /dev/mem",
            "artifact staging is not boot, shutdown, rollback, or target-ABI proof",
        ],
    }


class DcentosInitSurfaceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.production = production_source(cls.source)
        cls.manifest = (CRATE_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    def test_registry_is_exactly_reproducible(self) -> None:
        self.assertEqual(self.registry, build_registry())

    def test_manifest_binary_and_private_root_surface_are_exact(self) -> None:
        self.assertIn('name = "dcentos-init"', self.manifest)
        self.assertIn('path = "src/main.rs"', self.manifest)
        self.assertNotIn("[features]", self.manifest)
        self.assertEqual(dependency_names(self.manifest), ["libc"])
        self.assertEqual(
            re.findall(
                r"^pub\s+(?:fn|struct|enum|trait|type|const|static|mod)\b",
                self.production,
                re.M,
            ),
            [],
        )
        self.assertEqual(self.registry["public_items"], 0)
        self.assertEqual(self.registry["binary_kind"], "private-surface-pid1")

    def test_private_function_and_type_inventory_is_exhaustive(self) -> None:
        functions = set(
            re.findall(
                r'^(?:extern "C" )?fn ([A-Za-z0-9_]+)', self.production, re.M
            )
        )
        grouped = {
            name
            for names in EXPECTED_FUNCTION_GROUPS.values()
            for name in names
        }
        self.assertEqual(functions, grouped)
        self.assertEqual(len(functions), 39)
        self.assertEqual(self.registry["private_function_count"], 39)
        for needle in (
            "enum ExternalMediaMarkerState",
            "enum ServicePosture",
            "struct ServicePassResult",
            "static SHUTDOWN_REQUESTED",
            "static SHUTDOWN_SIGNAL",
        ):
            self.assertIn(needle, self.production)

    def test_fixed_paths_service_order_console_and_watchdog_are_exact(self) -> None:
        self.assertEqual(fixed_policy(self.production), EXPECTED_FIXED_POLICY)
        self.assertEqual(self.registry["fixed_policy"], EXPECTED_FIXED_POLICY)

    def test_unit_test_accounting_and_host_boundary_are_exact(self) -> None:
        tests = set(
            re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", self.source)
        )
        self.assertEqual(tests, EXPECTED_TESTS)
        self.assertEqual(self.registry["compile_profiles"][0]["unit_tests"], 29)
        self.assertEqual(self.registry["compile_profiles"][0]["package_tests"], 29)
        self.assertEqual(
            self.registry["test_boundary"]["production_action_functions_executed"],
            [],
        )
        self.assertFalse(self.registry["test_boundary"]["device_or_kernel_contact"])
        test_source = self.source.split("#[cfg(test)]", 1)[1]
        for forbidden in (
            "arm_emergency_watchdog",
            "do_mount",
            "do_shutdown",
            "emergency_kernel_action",
            "ensure_console",
            "fallback_early_init",
            "fork_exec",
            "fork_exec_with_tty",
            "install_signal_handlers",
            "main",
            "mount_virtual_fs",
            "run_early_init",
            "spawn_getty",
            "unmount_all",
            "write_kernel_control_byte",
        ):
            self.assertNotRegex(test_source, rf"(?m)^\s*{forbidden}\s*\(")
        self.assertNotRegex(test_source, r"(?m)^\s*unsafe\s*\{")

    def test_unsafe_libc_and_action_authority_are_exact(self) -> None:
        self.assertIn("#![deny(unsafe_op_in_unsafe_fn)]", self.source)
        self.assertEqual(len(re.findall(r"\bunsafe\s*\{", self.production)), 35)
        calls = set(re.findall(r"libc::([A-Za-z0-9_]+)\s*\(", self.production))
        self.assertEqual(calls, EXPECTED_LIBC_CALLS)
        self.assertEqual(
            set(self.registry["unsafe_boundary"]["libc_call_census"]),
            EXPECTED_LIBC_CALLS,
        )
        self.assertEqual(
            {row["surface"] for row in self.registry["action_surfaces"]},
            {
                "filesystem_and_device_bootstrap",
                "pid1_and_signal_ownership",
                "recovery_console",
                "root_script_execution",
                "shutdown_and_process_sweep",
                "terminal_kernel_action",
            },
        )

    def test_fail_closed_boot_external_media_and_shutdown_order_is_pinned(self) -> None:
        for needle in (
            "if pid != 1",
            "install_signal_handlers();",
            "ExternalMediaMarkerState::Absent if early_init_succeeded",
            "ExternalMediaMarkerState::Unsafe => ServicePosture::ConsoleOnly",
            "match fs::symlink_metadata(EARLY_INIT)",
            "metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0",
            "metadata.dev() == candidate.dev() && metadata.ino() == candidate.ino()",
            "let fail_fast = posture == ServicePosture::ExternalRestricted && action == \"start\";",
            "arm_emergency_watchdog(rb_action, SHUTDOWN_WATCHDOG_MS);",
            "libc::kill(-1, libc::SIGTERM)",
            "libc::kill(-1, libc::SIGKILL)",
            "write_kernel_control_byte(b\"/proc/sysrq-trigger\\0\", trigger);",
        ):
            self.assertIn(needle, self.production)
        self.assertLess(
            self.production.index("install_signal_handlers();"),
            self.production.index("mount_virtual_fs();"),
        )
        self.assertLess(
            self.production.index("arm_emergency_watchdog(rb_action"),
            self.production.index("do_shutdown(service_posture"),
        )

    def test_artifact_staging_cross_targets_and_empty_ledger_scope_are_exact(self) -> None:
        self.assertEqual(artifact_consumers(), EXPECTED_ARTIFACT_CONSUMERS)
        self.assertEqual(self.registry["artifact_consumers"], EXPECTED_ARTIFACT_CONSUMERS)
        cross = (REPO_ROOT / ".github" / "workflows" / "cross-compile-matrix.yml").read_text(
            encoding="utf-8"
        )
        for target in self.registry["compile_targets"]:
            self.assertIn(target, cross)
        workspace_manifest = (DCENTOS_ROOT / "dcentrald" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
        default_members = workspace_manifest.split("default-members = [", 1)[1].split(
            "]", 1
        )[0]
        self.assertIn('"dcentos-init"', default_members)
        self.assertTrue(self.registry["workspace_default_member"])
        self.assertEqual(self.registry["ledger_rows"], [])
        self.assertEqual(self.registry["direct_rust_consumers"], [])

    def test_hosted_aggregate_and_campaign_own_the_complete_boundary(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cargo test --locked -p dcentos-init", workflow)
        aggregate = (DCENTOS_ROOT / "scripts" / "ci_offline_gates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/test_dcentos_init_surface_registry.py -q", aggregate)
        campaign = (
            REPO_ROOT
            / "docs"
            / "dev"
            / "2026-08-05-hardware-supremacy-campaign"
            / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("PID-1 surface registry convergence", campaign)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-registry", action="store_true")
    arguments, remaining = parser.parse_known_args()
    if arguments.write_registry:
        REGISTRY_PATH.write_text(
            json.dumps(build_registry(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(REGISTRY_PATH)
        return 0
    result = unittest.main(argv=[__file__, *remaining], exit=False)
    return 0 if result.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
