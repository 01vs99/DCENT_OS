#!/usr/bin/env python3
"""Regression tests for the normal-runtime hardware ownership boundary.

The mining runtime owns physical I2C/UART/UIO/devmem transports. Long-lived
web adapters, post-boot verification, normal REST handlers, and packaged
research tools must not create parallel owners. These tests deliberately pin
both source shape and final Buildroot composition.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_I2C_COMMAND = re.compile(r"\b(?:i2cget|i2cset|i2cdetect|i2cdump|i2ctransfer)\b")

WEB_ADAPTERS = (
    ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/root/web/server.py",
    ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/root/web/ip_reporter.py",
    ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/root/web/mcp_server.py",
    ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/server.py",
    ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/ip_reporter.py",
    ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/root/web/mcp_server.py",
)

S99_VERIFY_COPIES = (
    ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/init.d/S99verify",
    ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99verify",
    ROOT
    / "br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/init.d/S99verify",
)

PRUNE = (
    ROOT / "br2_external_dcentos/board/common/prune-runtime-research-tools.sh"
)
TARGET_SWITCH_FIRMWARE = (
    ROOT
    / "br2_external_dcentos/board/zynq/rootfs-overlay/usr/sbin/switch_firmware.py"
)
TARGET_SWITCH_FIRMWARE_SH = TARGET_SWITCH_FIRMWARE.with_suffix(".sh")
HOST_SWITCH_FIRMWARE = ROOT / "scripts/switch_firmware.py"
HOST_SWITCH_FIRMWARE_SH = ROOT / "scripts/switch_firmware.sh"
REST_LATE = ROOT / "dcentrald/dcentrald-api/src/rest/late.rs"
REST_ROUTES = ROOT / "dcentrald/dcentrald-api/src/rest.rs"
HAL_I2C = ROOT / "dcentrald/dcentrald-hal/src/i2c.rs"
HARDWARE_INFO = ROOT / "dcentrald/dcentrald/src/runtime/hardware_info.rs"
S19J_HYBRID = ROOT / "dcentrald/dcentrald/src/s19j_hybrid_mining.rs"
AM3_BB = ROOT / "dcentrald/dcentrald/src/am3_bb_mining.rs"
AMLOGIC_HAL = ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
SERIAL_MINING = ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
SAFETY_WATCHDOG = ROOT / "dcentrald/dcentrald/src/runtime/safety_watchdog.rs"
WATCHDOG_FEED_GATE = ROOT / "dcentrald/dcentrald/src/runtime/watchdog_feed_gate.rs"
TASK_GUARD = ROOT / "dcentrald/dcentrald/src/runtime/task_guard.rs"
DAEMON = ROOT / "dcentrald/dcentrald/src/daemon.rs"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def python_function(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            if segment is None:
                raise AssertionError(f"could not recover Python function {name}")
            return segment
    raise AssertionError(f"Python function {name} not found")


def rust_function(source: str, name: str) -> tuple[str, int, int]:
    match = re.search(rf"\b(?:async\s+)?fn\s+{re.escape(name)}\s*\(", source)
    if match is None:
        raise AssertionError(f"Rust function {name} not found")
    start = match.start()
    brace = source.find("{", match.end())
    if brace < 0:
        raise AssertionError(f"Rust function {name} has no body")
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1], start, index + 1
    raise AssertionError(f"Rust function {name} has an unterminated body")


class RuntimeHardwareOwnershipTests(unittest.TestCase):
    def test_amlogic_power_and_thermal_share_one_retained_bus1_owner(self) -> None:
        hal = read(AMLOGIC_HAL)
        serial = read(SERIAL_MINING).split("\n#[cfg(test)]\nmod tests {", 1)[0]
        safety_watchdog = read(SAFETY_WATCHDOG)
        watchdog_feed_gate = read(WATCHDOG_FEED_GATE)
        task_guard = read(TASK_GUARD)
        thread_guard = read(ROOT / "dcentrald/dcentrald/src/runtime/thread_guard.rs")
        hybrid = read(S19J_HYBRID)
        am3_bb = read(AM3_BB)
        daemon = read(DAEMON)
        rest = read(REST_LATE)

        self.assertIn("pub struct AmlogicPowerThermalService", hal)
        self.assertIn(
            "spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation",
            hal,
        )
        self.assertIn("read_lm75_temperature_register_at", hal)
        self.assertNotIn("pub fn read_board_temps(", hal)
        self.assertNotIn("pub fn enable_psu_pmbus(", hal)
        self.assertNotIn("I2cBus::open(APW_PMBUS", hal)
        self.assertNotIn("classify_with_probe", hal)
        self.assertIn("generic Platform construction is refused", hal)
        self.assertIn("pub struct AmlogicNoPicAdmission", hal)
        self.assertIn("nopic_profile_for_bosminer_toml", hal)
        self.assertIn("nopic_profile_for_dcentos_marker", hal)
        self.assertIn('nopic_profile_for_dcentos_marker("am3-aml"), None', hal)
        self.assertIsNone(re.search(r"(?m)^pub fn open_fan_controller\(\)", hal))
        self.assertIsNone(re.search(r"(?m)^pub fn spawn\(\) -> Result<Self>", hal))

        # The former NoPic detect() call was split into the original mapped
        # S19k owner and exact modern S21 population admission. Check each
        # retained service/fan/power branch in the actual run function.
        run, _, _ = rust_function(serial, "run")
        bm1398_refusal = run.index("if is_bm1398 && !passthrough")
        bm1366_refusal = run.index("if is_bm1366 && !passthrough")
        observation = run.index(
            "let nopic = if s19k_install_custody_safeoff || is_bm1362_aml || is_bm1366_xp {"
        )
        s19k_admission = run.index("S19kNativeAggregateAdmission::detect()")
        mapped = run.index(".into_population()", s19k_admission)
        s19k_service = run.index("mapped.spawn_power_thermal_service()", mapped)
        modern_admission = run.index("AmlogicNoPicAdmission::detect_modern_s21_population(profile)")
        modern_service = run.index(".spawn_power_thermal_service()", modern_admission)
        s19k_fan = run.index(".open_fan_controller()", modern_service)
        modern_fan = run.index(".open_fan_controller()", s19k_fan + 1)
        self.assertLess(bm1398_refusal, observation)
        self.assertLess(bm1366_refusal, observation)
        self.assertLess(observation, s19k_admission)
        self.assertLess(observation, modern_admission)
        self.assertLess(s19k_admission, mapped)
        self.assertLess(mapped, s19k_service)
        self.assertLess(s19k_service, s19k_fan)
        self.assertLess(modern_admission, modern_service)
        self.assertLess(modern_service, modern_fan)

        s19k = run[run.index('"native S19k cold-start lacks exact NoPic power ownership"'):]
        s19k = s19k[:s19k.index("let powered_thermal_port =")]
        arm = s19k.index("SafetyWatchdogOwner::start_before_energizing")
        lifecycle = s19k.index(".take_lifecycle_owner()")
        terminal = s19k.index(".admit_s19k_native_terminal_custody()")
        reset = s19k.index("mapped_for_reset.assert_all_resets_checked()")
        operation = s19k.index(".take_psu_enable_operation()")
        enable = s19k.index("psu_enable_operation.enable_psu_at_voltage(voltage)")
        self.assertLess(s19k_fan, run.index('"native S19k cold-start lacks exact NoPic power ownership"'))
        self.assertLess(arm, lifecycle)
        self.assertLess(lifecycle, terminal)
        self.assertLess(terminal, reset)
        self.assertLess(reset, operation)
        self.assertLess(operation, enable)

        modern_start = run.index("if !native_nopic_power_owner")
        modern = run[modern_start:]
        modern = modern[:modern.index("let startup_thermal_owner =")]
        lifecycle = modern.index(".take_lifecycle_owner()")
        operation = modern.index(".take_psu_enable_operation()")
        arm = modern.index("SafetyWatchdogOwner::start_before_energizing")
        enable = modern.index("psu_enable_operation.enable_psu_at_voltage(selected_rail_v)")
        compatibility_enable = modern.index("psu_enable_operation.enable_psu()")
        self.assertLess(modern_fan, modern_start)
        self.assertLess(lifecycle, operation)
        self.assertLess(operation, arm)
        self.assertLess(arm, enable)
        self.assertLess(arm, compatibility_enable)
        self.assertIn("power_thermal.thermal_port()", serial)
        self.assertNotIn("power_thermal.terminal_fence()", serial)
        self.assertIn(
            "management_fabric: dcentrald_hal::i2c::I2cServiceCloseReceipt",
            serial,
        )
        self.assertIn("NoPicWatchdogShutdownManifest::new", serial)
        self.assertIn("WatchdogDisarmPermit::from_nopic_manifest", serial)
        self.assertIn("mod serial_route_domains", serial)
        self.assertIn("SerialRouteDomains::claim", serial)
        self.assertIn(".begin_closeout()", serial)
        self.assertIn("composition: Option<WatchdogComposition>", safety_watchdog)
        self.assertIn("fn claim_composition(", safety_watchdog)
        self.assertIn("claim_hybrid_route_scope", safety_watchdog)
        self.assertIn("claim_am3_bb_route_scope", safety_watchdog)
        self.assertIn("self.composition != Some(permit.composition)", safety_watchdog)
        self.assertIn("issue_am2_never_energized", safety_watchdog)
        self.assertIn("evidence.run_scope.same_run(&self.run_scope)", safety_watchdog)
        self.assertNotIn("fn run_scope(&self) -> &WatchdogRunScope", safety_watchdog)
        self.assertIn("pub(crate) struct TaskReapSummary", task_guard)
        self.assertIn(
            "pub(crate) async fn reap_finished(&mut self) -> TaskReapSummary",
            task_guard,
        )
        self.assertIn("pub(crate) struct StandardMiningTaskGuard", task_guard)
        self.assertIn(
            "pub(crate) struct StandardMiningActorQuiescenceReceipt", task_guard
        )
        self.assertIn("pub(crate) struct StandardWatchdogRunAdmission", safety_watchdog)
        self.assertIn("pub(crate) struct StandardMiningActorIssuer", safety_watchdog)
        self.assertIn("issuer: StandardMiningActorIssuer", task_guard)
        self.assertIn("issuer.into_identity()", task_guard)
        self.assertNotIn("let issuer = Arc::new(())", task_guard)
        self.assertIn(
            "self.started[StandardMiningActorSlot::WorkDispatcher.index()]",
            task_guard,
        )
        self.assertIn(
            "report.outcome == TaskStopOutcome::Completed", task_guard
        )
        self.assertIn("pub(crate) trait FixedThreadSlot", thread_guard)
        self.assertIn("pub(crate) fn reserve(&mut self, slot: S)", thread_guard)
        self.assertIn("ThreadSlotState::StartFailed", thread_guard)
        self.assertIn(".take_actor_owner()", hybrid)
        self.assertIn("actor_owner.activate(self.shutdown.clone())", hybrid)
        self.assertIn("HybridThreadSlot::PsuHeartbeat", hybrid)
        self.assertIn("HybridThreadSlot::PicHeartbeat", hybrid)
        self.assertIn("let actor_receipt = feeder_stop.into_receipt()", hybrid)
        hybrid_manifest = safety_watchdog.split(
            "pub(crate) struct HybridWatchdogShutdownManifest", 1
        )[1].split("/// Exact move-only AM3-BB closeout roster", 1)[0]
        self.assertIn(
            "actors: ThreadRosterQuiescenceReceipt<HybridThreadSlot>",
            hybrid_manifest,
        )
        self.assertNotIn("actors: ThreadStopSummary", hybrid_manifest)
        self.assertIn("actor_owner.activate(worker_stop)", am3_bb)
        self.assertIn(
            "threads.reserve(Am3BbThreadSlot::DspicHeartbeat)", am3_bb
        )
        am3_manifest = safety_watchdog.split(
            "pub(crate) struct Am3BbWatchdogShutdownManifest", 1
        )[1].split("/// Move-only standard-daemon authority", 1)[0]
        self.assertIn(
            "actors: ThreadRosterQuiescenceReceipt<Am3BbThreadSlot>",
            am3_manifest,
        )
        self.assertNotIn("actors: ThreadStopSummary", am3_manifest)
        self.assertIn(
            "api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt",
            am3_manifest,
        )
        self.assertIn("WatchdogDisarmPermit::from_am3_bb_manifest", am3_bb)

        am3_guard = am3_bb.split("impl Am3BbRunSafetyGuard", 1)[1].split(
            "impl Drop for Am3BbRunSafetyGuard", 1
        )[0]
        self.assertLess(
            am3_guard.index("am3_bb_prepare_board_cutoff_set("),
            am3_guard.index(".open_fan()"),
        )
        self.assertIn('writer.write_all(b"low")', am3_bb)
        self.assertIn('.write_all(b"1")', am3_bb)
        self.assertNotIn("write_level_checked", am3_bb)

        am3_run, _, _ = rust_function(am3_bb, "run_am3_bb_blocking")
        teardown_request = am3_run.index(".request_teardown_budget()")
        retained_cut = am3_run.index(
            ".cut_board_enable_checked(teardown_view.clone())"
        )
        teardown_ack = am3_run.index("watchdog.observe_teardown_admission(")
        api_drain = am3_run.index(".close_and_drain_until(api_drain_deadline)")
        self.assertLess(teardown_request, retained_cut)
        self.assertLess(retained_cut, teardown_ack)
        self.assertLess(teardown_ack, api_drain)

        watchdog_request, _, _ = rust_function(
            safety_watchdog, "request_teardown_budget"
        )
        self.assertIn("publish_deadline(deadline)", watchdog_request)
        self.assertIn("WatchdogCommand::BeginTeardown", watchdog_request)
        self.assertNotIn(".await", watchdog_request)
        self.assertNotIn(".lock()", watchdog_request)
        self.assertIn("deadline_request: Arc<OnceLock<Instant>>", watchdog_feed_gate)
        self.assertIn("self.deadline_request.set(deadline)", watchdog_feed_gate)

        panic_cut, _, _ = rust_function(
            am3_bb, "am3_bb_panic_hook_best_effort_teardown"
        )
        self.assertLess(
            panic_cut.index("watchdog_feed_stop.close_terminal_lock_free()"),
            panic_cut.index("cut_raw_noalloc()"),
        )
        self.assertLess(
            panic_cut.index("cut_raw_noalloc()"),
            panic_cut.index("for &gpio in &params.reset_gpios"),
        )
        self.assertIn("StandardMiningActorSlot::WorkDispatcher", daemon)
        self.assertIn("StandardMiningActorSlot::ThermalController", daemon)
        standard_manifest = daemon.split(
            "pub(crate) struct StandardDaemonShutdownEvidence", 1
        )[1].split("impl StandardDaemonShutdownEvidence", 1)[0]
        self.assertIn("StandardMiningActorQuiescenceReceipt", standard_manifest)
        self.assertNotIn("TaskStopSummary", standard_manifest)
        nopic_manifest = safety_watchdog.split(
            "pub(crate) struct NoPicWatchdogShutdownManifest", 1
        )[1].split("impl NoPicWatchdogShutdownManifest", 1)[0]
        am2_manifest = safety_watchdog.split(
            "pub(crate) struct Am2SerialWatchdogShutdownManifest", 1
        )[1].split("impl Am2SerialWatchdogShutdownManifest", 1)[0]
        self.assertIn(
            "actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>",
            nopic_manifest,
        )
        self.assertIn(
            "actors: ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>",
            am2_manifest,
        )
        for manifest in (nopic_manifest, am2_manifest):
            self.assertIn("SerialExecutionDomainCloseout", manifest)
            self.assertIn("ApiMutationDomainCloseout", manifest)
            self.assertNotIn("actors: ThreadStopSummary", manifest)
            self.assertNotIn("Option<", manifest)
            self.assertNotIn("HardwareMutationBarrierReceipt", manifest)
            self.assertNotIn("HardwareMutationCommitFenceReceipt", manifest)
        self.assertIn("pub(crate) enum NoPicSerialThreadSlot", safety_watchdog)
        self.assertIn("pub(crate) enum Am2SerialThreadSlot", safety_watchdog)
        self.assertIn("pub(crate) enum SerialWatchdogRouteAdmission", safety_watchdog)
        self.assertIn(
            ".and_then(|owner| runtime_threads.activate_nopic(owner));", serial
        )
        self.assertIn(
            ".and_then(|owner| runtime_threads.activate_am2(owner));", serial
        )
        self.assertIn("runtime_threads.spawn_pic_heartbeat(||", serial)
        self.assertIn("SerialActorTopology::admit(", serial)
        self.assertIn(
            "exact direct-serial routes refuse the experimental uart_trans actor before hardware admission",
            serial,
        )
        self.assertIn("failure_with_exact_serial_closeout(", serial)
        self.assertNotIn(
            'expect("BM1362 serial domain was revoked before first-stage cutoff")',
            serial,
        )
        self.assertNotIn(
            'expect("BM1362 route creates serial revocation evidence")',
            serial,
        )
        self.assertIn(
            "exact serial route reached terminal shutdown without retained watchdog ownership",
            serial,
        )
        self.assertIn("runtime_threads.spawn_serial_io(thread_name", serial)
        self.assertEqual(
            serial.count(".reserve_am2(Am2SerialThreadSlot::ApwHeartbeat)?"),
            2,
        )
        self.assertNotIn("runtime_threads.push(", serial)
        self.assertIn("struct NoPicEmergencyCutReceipt", serial)
        self.assertIn(
            "fn first_stage_safe_off(&self) -> Result<NoPicEmergencyCutReceipt>",
            serial,
        )
        self.assertIn(
            "let mut early_safe_off_receipt: Option<NoPicEmergencyCutReceipt> = None;",
            serial,
        )
        emergency_cut, _, _ = rust_function(
            serial, "checked_nopic_emergency_safe_off"
        )
        self.assertIn("guard.first_stage_safe_off()", emergency_cut)
        self.assertNotIn("guard.safe_off()", emergency_cut)
        failure_closeout, _, _ = rust_function(
            serial, "closeout_native_nopic_failure"
        )
        self.assertIn(
            "prior_emergency_cut: Option<NoPicEmergencyCutReceipt>",
            failure_closeout,
        )
        self.assertIn(
            '"NoPic failure checked safe-off"', failure_closeout
        )
        self.assertNotIn("Some(receipt) => Ok(receipt)", failure_closeout)
        shutdown = serial.split('info!("=== SHUTDOWN ===");', 1)[1]
        prior_cut_discard = shutdown.index(
            "let _prior_emergency_cut = early_safe_off_receipt.take();"
        )
        repeated_cut = shutdown.index(
            '"NoPic operator-stop first-stage safe-off"'
        )
        timed_cut_validation = shutdown.index(
            "ExactSerialTeardownProgress::after_nopic_checked_cut("
        )
        self.assertLess(prior_cut_discard, repeated_cut)
        self.assertLess(repeated_cut, timed_cut_validation)
        self.assertIn("owner.latch_terminal_safe_off();", serial)
        self.assertIn(".close_and_join_until(management_fabric_deadline)", serial)
        self.assertNotIn("amlogic::read_board_temps(", serial)
        self.assertNotIn("amlogic::AmlogicPlatform::new()", serial)

        self.assertNotIn("platform::amlogic::enable_psu()", daemon)
        self.assertIn("does not own the retained Amlogic power/thermal service", daemon)
        recovery_psu, _, _ = rust_function(rest, "post_debug_psu_control_recovery")
        self.assertNotIn("platform::amlogic::enable_psu()", recovery_psu)
        self.assertNotIn("platform::amlogic::disable_psu()", recovery_psu)
        self.assertIn("retained, polarity-aware power owner", recovery_psu)
        self.assertIn("terminal fence", recovery_psu)
        self.assertIn('"hardware_access_attempted": false', recovery_psu)

    def test_hybrid_eeprom_gate_stays_inside_owned_i2c_service(self) -> None:
        hal = read(HAL_I2C)
        hardware_info = read(HARDWARE_INFO)
        hybrid = read(S19J_HYBRID)

        service_reader, _, _ = rust_function(
            hardware_info,
            "read_hashboard_eeprom_prefix_via_service_for_energize_gate",
        )
        hal_reader, _, _ = rust_function(hal, "read_protected_hashboard_eeprom_span")
        self.assertIn("0x50u8", service_reader)
        self.assertIn(
            "service.read_hashboard_eeprom_prefix_at(addr, deadline)", service_reader
        )
        self.assertIn("is_retryable_owned_eeprom_readiness_error", service_reader)
        self.assertIn("OwnedEepromReadinessError::Terminal", service_reader)
        self.assertIn("HalError::I2cEndpointNotReady", hardware_info)
        self.assertNotIn("std::fs", service_reader)
        self.assertNotIn("/sys/bus/i2c", service_reader)
        self.assertIn("if !self.is_write_denied(addr)", hal_reader)
        self.assertIn("open_at24_identity_file(std::path::Path::new(&device))", hal_reader)
        at24_selector, _, _ = rust_function(hal, "open_at24_identity_file")
        self.assertIn('fs::File::open(device.join("eeprom"))', at24_selector)
        self.assertIn('fs::symlink_metadata(device.join("driver"))', at24_selector)
        self.assertIn("std::io::ErrorKind::PermissionDenied", at24_selector)
        self.assertIn("let mut offset = [0u8];", hal_reader)
        self.assertIn("I2C_RDWR", hal_reader)
        self.assertIn("nmsgs: 2", hal_reader)
        self.assertIn("if completed != 2", hal_reader)
        self.assertNotIn("set_slave", hal_reader)
        self.assertNotIn("I2C_SLAVE", hal_reader)

        run = hybrid.split("pub async fn run(&mut self)", 1)[1]
        run = run.split("fn log_am2_planned_chain_contexts", 1)[0]
        self.assertEqual(
            run.count("read_hashboard_eeprom_prefix_via_service_for_energize_gate("),
            1,
        )
        self.assertEqual(run.count("read_hashboard_eeprom_prefix_at("), 1)
        self.assertNotIn("read_bytes(0x50", run)
        self.assertNotIn("read_hashboard_eeprom_for_energize_gate(", run)
        self.assertIn("HalError::I2cEndpointNotReady", run)
        self.assertIn(
            "AM2 hashboard EEPROM bootstrap service failed terminally", run
        )
        self.assertIn("OwnedEepromReadinessError::Terminal", run)
        self.assertIn("am2-hashboard-eeprom-service-terminal", run)
        self.assertIn(
            'context("AM2 I2C service missing for serialized hashboard identity reads")',
            run,
        )

        self.assertIn("pub fn read_hashboard_eeprom_prefix_at(", hal)
        self.assertIn("I2cRequest::ReadHashboardEepromSpan", hal)
        self.assertIn("read_protected_hashboard_eeprom_span", hal)
        self.assertNotIn("WriteReadProtection", hal)

        # The full-page read added for the deployed-EEPROM decoder must stay
        # inside the same owned service, under the same admission, and must not
        # become a caller-controlled length. `HashboardEepromSpan` is a closed
        # two-value set: the worker derives the transfer size from the variant,
        # so widening the read cannot widen the reachable surface.
        self.assertIn("pub fn read_hashboard_eeprom_page_at(", hal)
        self.assertIn("pub enum HashboardEepromSpan", hal)
        self.assertIn("IdentityPrefix", hal)
        self.assertIn("FullPage", hal)
        # The page length is single-sourced from the decoder that consumes it.
        # If these drift the transport still "succeeds" and only the decoder
        # refuses, which is exactly how the missing full-page read stayed
        # invisible in the first place.
        self.assertIn(
            "HASHBOARD_EEPROM_PAGE_LEN: usize = "
            "dcentrald_api_types::deployed_eeprom::RAW_PAGE_LEN",
            hal,
        )
        # The energize gate reads the 32-byte prefix; widening that constant
        # would change a safety path rather than add a capability beside it.
        self.assertIn("HASHBOARD_EEPROM_PREFIX_LEN: usize = 32", hal)

        page_reader, _, _ = rust_function(hal, "read_hashboard_eeprom_span_at")
        self.assertIn("I2cRequest::ReadHashboardEepromSpan", page_reader)
        self.assertIn("I2cOperationIntent::ReadOnly", page_reader)
        self.assertNotIn("std::fs", page_reader)
        self.assertNotIn("/sys/bus/i2c", page_reader)

        # Both public spans are thin delegations, so neither can acquire its own
        # transport or skip the endpoint-range check in the shared submitter.
        for public_reader in (
            "read_hashboard_eeprom_prefix_at",
            "read_hashboard_eeprom_page_at",
        ):
            body, _, _ = rust_function(hal, public_reader)
            self.assertIn("self.read_hashboard_eeprom_span_at(", body)
            self.assertNotIn("fs::File::open", body)

    def test_web_adapters_have_no_raw_hardware_command_path(self) -> None:
        for path in WEB_ADAPTERS:
            with self.subTest(path=path):
                source = read(path)
                self.assertIsNone(RAW_I2C_COMMAND.search(source))

        for path in (WEB_ADAPTERS[0], WEB_ADAPTERS[3]):
            source = read(path)
            self.assertNotIn("_refresh_i2c_temps", source)
            self.assertNotIn("threading.Thread", source)
            self.assertNotIn("devmem", source)
            self.assertNotIn("/sys/class/gpio/export", source)
            self.assertNotIn("dcentrald_fan_cmd", source)
            self.assertNotIn("--get-fan", source)
            self.assertNotIn("--set-fan", source)

        fail_closed_tools = (
            "tool_get_fpga_registers",
            "tool_read_devmem",
            "tool_write_fpga_register",
            "tool_write_devmem",
            "tool_gpio_read",
            "tool_gpio_write",
            "tool_board_control",
            "tool_set_fan_speed",
        )
        for path in WEB_ADAPTERS[2::3]:
            source = read(path)
            for name in fail_closed_tools:
                with self.subTest(path=path, function=name):
                    body = python_function(source, name)
                    self.assertIn("_raw_hardware_unavailable", body)
                    self.assertNotIn("subprocess", body)
                    self.assertNotIn("run_cmd", body)
                    self.assertNotIn("open(", body)
            fan_read = python_function(source, "tool_get_fan_speed")
            self.assertIn("tool_live_stats", fan_read)
            self.assertIn("dcentrald /api/status", fan_read)
            self.assertNotIn("/sys/class/gpio/export", source)
            self.assertNotRegex(source, r"run_cmd\([^\n]*(?:devmem|/dev/(?:mem|uio|tty|i2c))")

        zynq_mcp = read(WEB_ADAPTERS[2])
        uart = python_function(zynq_mcp, "tool_capture_chain_uart_bytes")
        self.assertIn("_raw_hardware_unavailable", uart)
        self.assertNotIn("open(", uart)

    def test_s99_is_a_fail_closed_snapshot_consumer_and_never_commits(self) -> None:
        mutation_command = re.compile(
            r"(?m)^\s*(?:fw_setenv|nandwrite|flash_erase)(?:\s|$)"
        )
        for path in S99_VERIFY_COPIES:
            with self.subTest(path=path):
                source = read(path)
                self.assertIsNone(RAW_I2C_COMMAND.search(source))
                self.assertIsNone(mutation_command.search(source))
                self.assertNotIn('"$DAEMON" --get-fan', source)
                self.assertIn("http://127.0.0.1:8080/api/status", source)
                self.assertIn("raw fallback is prohibited", source)
                self.assertIn("S99verify is a report-only proof consumer", source)
                self.assertIn("UPGRADE_COMMIT_MARKER", source)
                self.assertIn("upgrade-commit-state", source)
                self.assertIn(
                    'emit_check V12 false "am3-aml: state.json missing', source
                )
                self.assertIn(
                    'emit_check V13 false "no daemon-owned $evt counter', source
                )

    def test_rest_normal_routes_are_safe_and_recovery_bodies_are_unmounted(self) -> None:
        source = read(REST_LATE)
        routes = read(REST_ROUTES)
        cargo = read(ROOT / "dcentrald/dcentrald-api/Cargo.toml")
        self.assertIn('recovery-tool = ["dcentrald-common/lab"]', cargo)
        self.assertNotIn('Command::new("i2ctransfer")', source)
        self.assertNotIn("PsuController::open_kernel_only", source)

        normal_handlers = (
            "post_offgrid_test",
            "get_debug_registers",
            "post_debug_psu_control",
            "get_diag_fpga",
        )
        for name in normal_handlers:
            with self.subTest(handler=name):
                body, _, _ = rust_function(source, name)
                self.assertNotIn('Command::new("devmem")', body)
                self.assertNotIn("create_voltage_source", body)
                self.assertNotIn("AmlogicPsu", body)
                self.assertNotIn("ZynqPsu", body)
                self.assertIn("hardware_access_attempted", body)

        recovery_handlers = (
            "post_offgrid_test_recovery",
            "get_debug_registers_recovery",
            "post_debug_psu_control_recovery",
            "get_diag_fpga_recovery",
        )
        masked = list(source)
        for name in recovery_handlers:
            body, start, end = rust_function(source, name)
            prefix = source[max(0, start - 100) : start]
            self.assertIn('#[cfg(feature = "recovery-tool")]', prefix)
            self.assertNotIn(name, routes)
            masked[start:end] = " " * (end - start)

        normal_source = "".join(masked)
        self.assertNotIn('Command::new("devmem")', normal_source)
        self.assertNotIn("create_voltage_source", normal_source)

        fan_write, _, _ = rust_function(source, "set_fan_pwm_via_hal")
        fan_read, _, _ = rust_function(source, "read_fan_via_hal")
        self.assertIn("serialized command broker", fan_write)
        self.assertIn("runtime telemetry snapshot", fan_read)
        self.assertNotIn("FanController::open", fan_write + fan_read)

    def test_every_product_runs_prune_as_the_final_post_build_stage(self) -> None:
        configs = sorted((ROOT / "br2_external_dcentos/configs").glob("*_defconfig"))
        product_configs = [path for path in configs if "BR2_ROOTFS_OVERLAY=" in read(path)]
        self.assertTrue(product_configs)
        for path in product_configs:
            with self.subTest(path=path):
                post_build = next(
                    (
                        line
                        for line in read(path).splitlines()
                        if line.startswith("BR2_ROOTFS_POST_BUILD_SCRIPT=")
                    ),
                    "",
                )
                self.assertRegex(
                    post_build,
                    r"board/common/prune-runtime-research-tools\.sh\"$",
                )

        common = read(ROOT / "br2_external_dcentos/configs/dcentos-common.fragment")
        cv_defconfig = (
            ROOT
            / "br2_external_dcentos/configs/dcentos_cv1835_s19jpro_defconfig"
        )
        self.assertIn("# BR2_PACKAGE_I2C_TOOLS is not set", common)
        self.assertNotIn("BR2_PACKAGE_I2C_TOOLS=y", common)
        self.assertFalse(
            cv_defconfig.exists(),
            "CV1835 must not regain a Buildroot product lane before its exact toolchain and containment contract are admitted",
        )

        prune = read(PRUNE)
        self.assertIn('TARGET_DIR=$(CDPATH= cd "$TARGET_DIR" && pwd -P)', prune)
        self.assertIn("Buildroot rootfs sentinels", prune)
        self.assertIn("symlinked delete-path component", prune)
        self.assertIn('rm -rf "$TARGET_DIR/root/tools"', prune)
        self.assertIn('rm -f "$TARGET_DIR/usr/bin/dcent-shell"', prune)
        self.assertIn("root usr usr/bin usr/sbin", prune)
        self.assertIn('"$TARGET_DIR/usr/sbin/switch_firmware.py"', prune)
        self.assertIn('"$TARGET_DIR/usr/sbin/switch_firmware.sh"', prune)
        self.assertIn("DCENT_RELEASE_IMAGE", prune)
        self.assertIn("usr/bin/strace", prune)
        self.assertIn("usr/sbin/i2cget", prune)

    def test_raw_boot_environment_transformers_are_host_only(self) -> None:
        self.assertFalse(TARGET_SWITCH_FIRMWARE.exists())
        self.assertFalse(TARGET_SWITCH_FIRMWARE_SH.exists())
        self.assertTrue(HOST_SWITCH_FIRMWARE.is_file())
        self.assertTrue(HOST_SWITCH_FIRMWARE_SH.is_file())

        post_builds = sorted(
            (ROOT / "br2_external_dcentos/board").rglob("post-build.sh")
        )
        self.assertTrue(post_builds)
        for post_build in post_builds:
            with self.subTest(post_build=post_build):
                self.assertNotIn("switch_firmware", read(post_build))

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "requires POSIX sh")
    def test_prune_composes_a_safe_rootfs_and_rejects_symlink_escape(self) -> None:
        self.assertTrue(PRUNE.stat().st_mode & stat.S_IXUSR)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            for directory in (
                target / "etc",
                target / "bin",
                target / "usr/bin",
                target / "usr/sbin",
                target / "root/tools/__pycache__",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            (target / "root/tools/future_raw_executor").write_text("raw\n")
            (target / "root/tools/__pycache__/raw.pyc").write_bytes(b"bytecode")
            (target / "usr/bin/dcent-shell").write_text("shell\n")
            (target / "usr/sbin/switch_firmware.py").write_text("raw\n")
            (target / "usr/sbin/switch_firmware.sh").write_text("raw\n")
            (target / "usr/bin/strace").write_text("strace\n")
            (target / "usr/sbin/i2cget").write_text("i2cget\n")
            (target / "etc/preserved").write_text("safe\n")

            # WS-A4 re-anchor (2026-09-01): this case asserted the DEV default
            # (posture env unset => strace/i2cget survive). RELEASE is now the
            # DEFAULT posture, so the DEV preservation case must use the
            # explicit opt-out. The assertions are unchanged — nothing was
            # weakened; a new default-RELEASE case is added below.
            env = os.environ.copy()
            env.pop("DCENT_RELEASE_IMAGE", None)
            env.pop("DCENT_DEV_IMAGE", None)
            env["DCENT_DEV_IMAGE"] = "1"
            subprocess.run(["sh", str(PRUNE), str(target)], check=True, env=env)
            self.assertFalse((target / "root/tools").exists())
            self.assertFalse((target / "usr/bin/dcent-shell").exists())
            self.assertFalse((target / "usr/sbin/switch_firmware.py").exists())
            self.assertFalse((target / "usr/sbin/switch_firmware.sh").exists())
            self.assertEqual((target / "usr/bin/strace").read_text(), "strace\n")
            self.assertEqual((target / "usr/sbin/i2cget").read_text(), "i2cget\n")
            self.assertEqual((target / "etc/preserved").read_text(), "safe\n")

            # WS-A4: DEFAULT posture (env fully unset) => RELEASE: the debug
            # executors are pruned with no explicit request. Recreate them
            # first so this case is independent of the DEV case above.
            (target / "usr/bin/strace").write_text("strace\n")
            (target / "usr/sbin/i2cget").write_text("i2cget\n")
            env = os.environ.copy()
            env.pop("DCENT_RELEASE_IMAGE", None)
            env.pop("DCENT_DEV_IMAGE", None)
            subprocess.run(["sh", str(PRUNE), str(target)], check=True, env=env)
            self.assertFalse((target / "usr/bin/strace").exists())
            self.assertFalse((target / "usr/sbin/i2cget").exists())
            self.assertEqual((target / "etc/preserved").read_text(), "safe\n")

            env["DCENT_RELEASE_IMAGE"] = "1"
            subprocess.run(["sh", str(PRUNE), str(target)], check=True, env=env)
            self.assertFalse((target / "usr/bin/strace").exists())
            self.assertFalse((target / "usr/sbin/i2cget").exists())
            self.assertEqual((target / "etc/preserved").read_text(), "safe\n")

            root_result = subprocess.run(
                ["sh", str(PRUNE), "/"], capture_output=True, text=True, check=False
            )
            self.assertNotEqual(root_result.returncode, 0)

            outside = base / "outside"
            outside.mkdir()
            (outside / "keeper").write_text("keep\n")
            unsafe = base / "unsafe"
            (unsafe / "etc").mkdir(parents=True)
            (unsafe / "bin").mkdir()
            (unsafe / "usr/bin").mkdir(parents=True)
            os.symlink(outside, unsafe / "root")
            escape_result = subprocess.run(
                ["sh", str(PRUNE), str(unsafe)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(escape_result.returncode, 0)
            self.assertEqual((outside / "keeper").read_text(), "keep\n")

    def test_runtime_package_and_shell_do_not_reinstall_raw_tools(self) -> None:
        package = read(ROOT / "br2_external_dcentos/packages/dcentos-tools/dcentos-tools.mk")
        self.assertNotIn("$(@D)/*.py", package)
        self.assertNotIn("$(@D)/*.sh", package)
        self.assertNotIn("usr/bin/dcent-shell", package)

        shell = read(ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/etc/bash.bashrc")
        profile = read(ROOT / "br2_external_dcentos/board/zynq/rootfs-overlay/root/.profile")
        self.assertIsNone(RAW_I2C_COMMAND.search(shell + profile))
        self.assertNotIn("devmem", shell + profile)
        self.assertNotIn("/dev/tty", shell + profile)
        self.assertNotIn("/root/tools", profile)
        self.assertIn("miner-status", shell)


if __name__ == "__main__":
    unittest.main()
