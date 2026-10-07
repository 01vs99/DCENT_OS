#!/usr/bin/env python3
"""Host-only verifier for the joined S19k native cold-start owner.

The source audit proves the exact move-only production composition. Workflow
verification also binds prerequisite receipts and one AArch64 ``dcentrald``
artifact. This script never opens devices, contacts a target, or grants live,
mining, NAND, or key-extraction authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Any, Mapping, NoReturn, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_native_build_verify as native_build  # noqa: E402

REPO_ROOT = SCRIPT_DIR.parent.parent.parent
DEFAULT_EVIDENCE_DIR = REPO_ROOT / ".s19k-gauntlet-evidence/native-cold-start-owner"
SCHEMA = "dcentos.s19k-native-owner-implementation/v7"
INPUT_SCHEMA = "dcentos.s19k-native-owner-inputs/v7"
NATIVE_RE_SCHEMA = "dcentos.s19k-native-re-verification/v1"
NATIVE_HARDWARE_SCHEMA = "dcentos.s19k-native-hardware-verification/v1"
ENDURANCE_SCHEMA = "dcentos.s19k-endurance-host-verification/v1"
REPRODUCIBILITY_SCHEMA = "dcentos.s19k-native-build-reproducibility/v3"
INPUT_NAME = "inputs.json"
ARTIFACT_NAME = "dcentrald"
RECEIPT_NAME = "verification.json"
BUILD_RECEIPT_NAME = "native-build.json"
PHASE_FILES = (INPUT_NAME, ARTIFACT_NAME, BUILD_RECEIPT_NAME, RECEIPT_NAME)
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

POLICY_SOURCE = (
    "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/"
    "s19k_bm1366_nopic_beta.rs"
)
HAL_SOURCE = "DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
SERIAL_SOURCE = "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs"
NATIVE_IDENTITY_SOURCE = "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining/s19k_native_identity.rs"
RUST_TOOLCHAIN_SOURCE = "DCENT_OS_Antminer/dcentrald/rust-toolchain.toml"
CARGO_CONFIG_SOURCE = "DCENT_OS_Antminer/dcentrald/.cargo/config.toml"
CARGO_LOCK_SOURCE = "DCENT_OS_Antminer/dcentrald/Cargo.lock"
ZIG_CC_SOURCE = "DCENT_OS_Antminer/dcentrald/zig-cc-aarch64.sh"
ZIG_AR_SOURCE = "DCENT_OS_Antminer/dcentrald/zig-ar-aarch64.sh"
AARCH64_CHECK_SOURCE = "DCENT_OS_Antminer/scripts/s19k_aarch64_compile_check.sh"
NATIVE_BUILD_SOURCE = "DCENT_OS_Antminer/scripts/s19k_native_build_verify.py"
SOURCE_PATHS = native_build.SEMANTIC_SOURCE_PATHS
ADOPTED_ROUTE_ARTIFACT_SHA256S = {
    "fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b",
    "9570a9fcd8e8a2cff6f3d21902f6354666c5b337b7b260641e5b0baf9260b4d6",
}
PREREQUISITE_PHASE_IDS = (
    "native-secure-firmware-re",
    "native-hardware-contract",
    "adopted-endurance",
    "native-build-reproducibility",
)
PREREQUISITE_PATHS = {
    "native-secure-firmware-re": ("native-secure-firmware-re", "verification.json"),
    "native-hardware-contract": ("native-hardware-contract", "verification.json"),
    "adopted-endurance": (
        "adopted-endurance",
        "evidence",
        "HOST_ENDURANCE_VERIFICATION.kv",
    ),
    "native-build-reproducibility": (
        "native-build-reproducibility",
        "verification.json",
    ),
}
REQUIRED_OWNER_CAPABILITIES = (
    "identity",
    "cooling",
    "gpio437",
    "resets",
    "watchdog",
    "population_uart_admission",
    "rollback",
    "terminal_safe_off",
)


class NativeOwnerError(ValueError):
    """The source or evidence does not prove the exact owner contract."""


def fail(message: str) -> NoReturn:
    raise NativeOwnerError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex64(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        fail(f"{label} has an invalid size: {path}")
    return path.read_bytes()


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _json(data: bytes, label: str) -> dict[str, Any]:
    if data.startswith(b"\xef\xbb\xbf"):
        fail(f"{label} starts with a BOM")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict ASCII JSON: {error}")
    if not isinstance(value, dict) or data != canonical_json(value):
        fail(f"{label} must be a canonical JSON object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: Sequence[str], label: str) -> None:
    if set(value) != set(expected):
        fail(f"{label} keys are not exact")


def load_source_corpus(repo_root: Path = REPO_ROOT) -> dict[str, bytes]:
    root = repo_root.resolve()
    return {
        path: _read_regular(root.joinpath(*path.split("/")), MAX_SOURCE_BYTES, path)
        for path in SOURCE_PATHS
    }


def _decode(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not UTF-8: {error}")


def _line(text: str, needle: str, label: str) -> int:
    offset = text.find(needle)
    if offset < 0:
        fail(f"required source anchor is absent ({label}): {needle}")
    return text.count("\n", 0, offset) + 1


def _fact(path: str, text: str, needle: str, symbol: str) -> dict[str, Any]:
    return {"path": path, "line": _line(text, needle, symbol), "symbol": symbol}


def _section(text: str, start: str, end: str, label: str) -> str:
    begin = text.find(start)
    finish = text.find(end, begin + len(start))
    if begin < 0 or finish < 0 or finish <= begin:
        fail(f"{label} source boundary is absent or reordered")
    return text[begin:finish]


def _require_all(text: str, anchors: Sequence[str], label: str) -> None:
    for anchor in anchors:
        if anchor not in text:
            fail(f"{label} lost required anchor: {anchor}")


def _require_order(text: str, anchors: Sequence[str], label: str) -> None:
    cursor = -1
    for anchor in anchors:
        found = text.find(anchor, cursor + 1)
        if found < 0:
            fail(f"{label} lost/reordered safety anchor: {anchor}")
        cursor = found


def _mask_comments_and_strings(text: str) -> str:
    output: list[str] = []
    index = 0
    block_depth = 0
    in_string = False
    escaped = False
    while index < len(text):
        pair = text[index : index + 2]
        character = text[index]
        if block_depth:
            if pair == "/*":
                block_depth += 1
                output.extend("  ")
                index += 2
            elif pair == "*/":
                block_depth -= 1
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if character == "\n" else " ")
                index += 1
        elif in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            output.append("\n" if character == "\n" else " ")
            index += 1
        elif pair == "//":
            newline = text.find("\n", index)
            if newline < 0:
                output.extend(" " * (len(text) - index))
                break
            output.extend(" " * (newline - index))
            output.append("\n")
            index = newline + 1
        elif pair == "/*":
            block_depth = 1
            output.extend("  ")
            index += 2
        elif character == '"':
            in_string = True
            output.append(" ")
            index += 1
        else:
            output.append(character)
            index += 1
    return "".join(output)


def _audit_private_owner(serial: str) -> list[dict[str, Any]]:
    route = _section(
        serial,
        "mod serial_route_domains {",
        "\nuse serial_route_domains::SerialRouteDomains;",
        "serial route domain",
    )
    code = _mask_comments_and_strings(route)
    if re.search(
        r"\bpub(?:\s*\([^)]*\))?\s+struct\s+S19kNativePreSerialAdmission",
        code,
    ):
        fail("native pre-serial token became externally constructible")
    if code.count("S19kNativePreSerialAdmission {") != 2:
        fail("native pre-serial constructor set is not exact (declaration/join)")
    token_offset = code.find("struct S19kNativePreSerialAdmission")
    if re.search(
        r"#\s*\[\s*derive\s*\([^]]*(Clone|Copy|Default|Serialize|Deserialize)",
        code[max(0, token_offset - 200) : token_offset],
    ):
        fail("native pre-serial token gained a duplicating/deserializing derive")
    owner = _section(
        route,
        "pub(super) struct S19kNativeColdStartOwner {",
        "\n    /// Opaque coupling of the physical backend",
        "native cold-start owner",
    )
    _require_all(
        owner,
        (
            "pre_serial: Option<S19kNativePreSerialAdmission>",
            "_dispatch: crate::SerialRuntimeDispatchAdmission",
            "_identity: S19kNativeIdentityReceipt",
            "_pre_cooling: S19kNativeCoolingAdmission",
            "_powered_cooling: S19kNativeCoolingAdmission",
            "_post_cooling: S19kNativeCoolingAdmission",
            "_pre_thermal: S19kNativeThermalAdmission",
            "_powered_thermal: S19kNativeThermalAdmission",
            "_post_thermal: S19kNativeThermalAdmission",
            "_power_and_reset: dcentrald_hal::platform::amlogic::S19kNativePopulationResetRelease",
            "_terminal: S19kNativeTerminalCustodyAdmission",
            "domains.route == ExactSerialRoute::S19kNative",
            "dispatch.identity() == dcentrald_common::AsicProtocolIdentity::Bm1366",
            "bm1366_dispatch_admitted_serial_platform(",
            "dispatch.board_target() == platform.board_target()",
            "dispatch.board_target() == platform_profile.board_target",
            "platform_profile.expected_chips_per_uart",
            "== dcentrald_hal::platform::amlogic::S19K_NATIVE_EXPECTED_CHIPS_PER_UART",
            "identity.board_count == identity.profile.board_count()",
            "identity.physical_addresses == identity.profile.physical_addresses()",
            "identity.board_names == identity.profile.board_names()",
            "identity.eeprom_slots == identity.profile.eeprom_slots()",
            "identity.profile.eeprom_presence() == platform.populated_slots()",
            "platform.owns_reset_release(&power_and_reset)",
            "power_and_reset.released() == platform.logical_chain_routes()",
            "fn issue_pre_serial(&mut self)",
            ".take()",
        ),
        "native cold-start owner",
    )
    if "issue_s19k_native_pre_serial_for_test" in code:
        fail("a test bypass can still mint the native production token")
    if "std::env" in owner or "S19K_NATIVE_COLD_START_ENV" in owner:
        fail("environment state reached the private owner/token issuer")
    return [
        _fact(SERIAL_SOURCE, serial, "pub(super) struct S19kNativeColdStartOwner {", "opaque production owner"),
        _fact(SERIAL_SOURCE, serial, "fn issue_pre_serial(&mut self)", "move-only private token issuer"),
    ]


def _audit_hal(hal: str) -> dict[str, list[dict[str, Any]]]:
    aggregate = _section(
        hal,
        "impl S19kNativeAggregateAdmission",
        "impl S19kNativePopulationAdmission",
        "native aggregate admission",
    )
    _require_all(
        aggregate,
        (
            "service.psu_enable_operation_available = false;",
            "Result<Arc<S19kNativeFanObservation>>",
            "let routes = self.logical_chain_routes();",
            "Ok(S19kNativePopulationAdmission {",
            "generation: Arc::new(())",
        ),
        "read-only aggregate admission",
    )
    for forbidden in (
        "service.psu_enable_operation_available = true;",
        "take_psu_enable_operation",
        "set_amlogic_board_reset_checked",
    ):
        if forbidden in aggregate:
            fail(f"read-only aggregate gained mutation authority: {forbidden}")
    mapped = _section(
        hal,
        "impl S19kNativePopulationAdmission",
        "\nfn amlogic_slot_from_serial_device",
        "native mapped admission",
    )
    _require_all(
        mapped,
        (
            "AmlogicNoPicProfile::S19k",
            "Some(Arc::clone(&self.generation))",
            "service.psu_enable_operation_available = true;",
            "Result<Arc<dyn FanAccess>>",
            "power: ApwEnableReceipt",
            "power.native_generation.as_ref()",
            "Arc::ptr_eq(power_generation, &self.generation)",
            "for route in &self.routes",
            "set_amlogic_board_reset_checked(route.logical_chain, false)",
            "for route in S19K_NATIVE_LOGICAL_CHAIN_ROUTES",
            "set_amlogic_board_reset_checked(route.logical_chain, true)",
            "assert_s19k_native_all_resets_checked()",
            "reset_release_completed_at: Instant::now()",
            "Arc::ptr_eq(&self.generation, &release.generation)",
        ),
        "generation-bound mapped admission",
    )
    reset = _section(
        hal,
        "pub fn assert_s19k_native_all_resets_checked()",
        "\nimpl GpioAccess for AmlogicGpio",
        "native reset assertion",
    )
    _require_all(
        reset,
        (
            "for chain in 0..3u8",
            "set_amlogic_board_reset_checked(chain, true)",
            "let expected_gpio = GPIO_RESET_BASE + u32::from(chain)",
            "if !failures.is_empty()",
            "Ok(S19kNativeAllResetsAsserted { reset_gpios })",
        ),
        "checked reset trio",
    )
    _require_all(
        hal,
        (
            "pub const S19K_NATIVE_LOGICAL_CHAIN_ROUTES:",
            'uart: "/dev/ttyS3"',
            "logical_chain: 0",
            "logical_board_address: 1",
            "plug_gpio: 439",
            "reset_gpio: 454",
            "pub const S19K_NATIVE_EXPECTED_CHIPS_PER_UART: u8 = 77;",
            'amlogic_gpio437::resolve_drive_recipe("am3-s19k")',
            "disable_psu_checked_for_recipe(recipe)",
        ),
        "reviewed HAL physical contract",
    )
    return {
        "gpio437": [
            _fact(HAL_SOURCE, hal, "pub fn gpio437_recipe(&self)", "population-bound GPIO437 drive recipe"),
            _fact(HAL_SOURCE, hal, "pub fn disable_s19k_track1_psu_checked()", "explicit S19k raw-1 SafeOff"),
        ],
        "resets": [
            _fact(HAL_SOURCE, hal, "pub fn assert_s19k_native_all_resets_checked()", "checked reset trio"),
            _fact(HAL_SOURCE, hal, "pub fn release_mapped_resets_checked(", "mapped generation-bound reset release"),
        ],
        "population_uart_admission": [
            _fact(HAL_SOURCE, hal, "pub const S19K_NATIVE_LOGICAL_CHAIN_ROUTES", "reviewed profile-aware logical-chain route"),
        ],
    }


def _audit_serial(serial: str) -> dict[str, list[dict[str, Any]]]:
    owner_facts = _audit_private_owner(serial)
    fan_helper = _section(
        serial,
        "fn s19k_native_four_fan_rpm_admitted(",
        "\n#[allow(clippy::too_many_arguments)]",
        "native four-fan admission helper",
    )
    _require_all(
        fan_helper,
        (
            "let mut seen = [false; 4]",
            "seen.get_mut(usize::from(channel))",
            "if *slot || rpm < S19K_NATIVE_MIN_FAN_RPM",
            "*slot = true",
            "seen.into_iter().all(|present| present)",
        ),
        "native exact four-channel cooling admission",
    )
    _require_all(
        serial,
        (
            'const S19K_NATIVE_COLD_START_ENV: &\'static str = "DCENT_S19K_NATIVE_COLD_START";',
            'matches!(raw, Some("1"))',
            "const S19K_NATIVE_MIN_FAN_RPM: u32 = 2_000;",
            "const S19K_NATIVE_OWNER_EVIDENCE_MAX_AGE: Duration = Duration::from_secs(5);",
            "fn s19k_native_receipt_timeline_admitted(",
            "snapshot.available && snapshot.expected_channels == 4 && snapshot.readings.len() == 4",
            "s19k_native_four_fan_rpm_admitted(&readings)",
            "S19kNativeCoolingStage::PreWatchdog",
            "S19kNativeCoolingStage::PostPower",
            "S19kNativeCoolingStage::PostResetRelease",
            "SerialChainBackend::open(route.logical_chain, path, 115_200)",
            "serial.expected_chips_per_uart() == 77",
            "first.identity == geometry.identity",
            "first.observed_chip_count == geometry.observed_chip_count",
            "first.addresses == geometry.addresses",
            "native_exact_mapping: true",
            "static S19K_NATIVE_TEARDOWN_ARMED",
            "arm_s19k_native_teardown(fan_max_pwm)",
            "disarm_s19k_native_teardown_after_checked_terminal_reset_and_cut()",
            "if is_bm1366 {\n                S19K_NATIVE_MIN_FAN_RPM",
            "let thermal_started_at = nopic_energized_at.unwrap_or_else(Instant::now);",
        ),
        "native serial owner path",
    )
    _require_all(
        serial,
        (
            "fn s19k_native_request_from_dispatch(",
            'admission.board_target() == "am3-s19k"',
            "admission.identity() == dcentrald_common::AsicProtocolIdentity::Bm1366",
            "!self.s19k_native_cold_start_requested()",
        ),
        "configured native request retains exact dispatch binding",
    )
    constructor_flags = re.findall(
        r"Ok\(SerialWorkTransport::Multi\(MultiTtyTransport\s*\{.*?"
        r"native_exact_mapping:\s*(true|false),",
        serial,
        re.DOTALL,
    )
    if constructor_flags != ["true", "false"]:
        fail(
            "multi-UART work transport constructor set changed; expected only "
            "mapped-native true and Track-1 false"
        )
    bringup = _section(
        serial,
        "let native_bringup_result: Result<(",
        "\n            .await;",
        "native bring-up branch",
    )
    _require_order(
        bringup,
        (
            "SafetyWatchdogOwner::start_before_energizing",
            "runtime_threads.activate_nopic(actor_owner)",
            ".prepare_s19k_native_enable(",
            "assert_all_resets_checked()",
            "shutdown raced native S19k reset assertion",
            "let voltage = f64::from(self.config.mining.voltage_mv) / 1000.0;",
            "psu_enable_operation.enable_psu_at_voltage(voltage)",
            "S19kNativeCoolingStage::PostPower",
            "shutdown raced native S19k powered cooling",
            "release_mapped_resets_checked(asserted, enable_receipt)",
            "S19kNativeCoolingStage::PostResetRelease",
            "S19kNativeColdStartOwner::join(",
            "promote_s19k_native_cold_start(&mut cold_owner)",
            "Self::init_bm1366_chains(native_backends, target_freq)",
            "shutdown arrived during native S19k population cold init",
            "native_backends.into_work_transport()",
        ),
        "native cold-start mutation/cancellation",
    )
    closeout = _section(
        serial,
        "impl NoPicPsuGuard {",
        "\nasync fn checked_nopic_emergency_safe_off",
        "native power guard",
    )
    _require_all(
        closeout,
        (
            "self.s19k_native_reset_before_cut = true",
            "assert_s19k_native_all_resets_checked",
            "latch_terminal_and_disable_psu_checked",
            "impl Drop for NoPicPsuGuard",
        ),
        "native reset-before-cut guard",
    )
    panic = _section(
        serial,
        "pub fn nopic_panic_hook_best_effort_teardown()",
        "\ntrait Am2FirstStagePowerCut",
        "native panic teardown",
    )
    _require_order(
        panic,
        (
            "native_armed || track1_armed",
            "assert_s19k_native_all_resets_checked",
            "disable_s19k_track1_psu_checked",
        ),
        "native panic reset-before-cut",
    )
    pre_actor = _section(
        serial,
        "let work_queue: Arc<Mutex<VecDeque<SerialQueuedTx>>>",
        "let serial_io_result = runtime_threads.spawn_serial_io",
        "native pre-actor cancellation",
    )
    _require_order(
        pre_actor,
        (
            "if is_bm1366 && !passthrough && self.shutdown.is_cancelled()",
            "failure_with_exact_serial_closeout(",
            "return Err(error);",
        ),
        "native pre-actor cancellation",
    )
    return {
        "identity": owner_facts,
        "cooling": [
            _fact(SERIAL_SOURCE, serial, "const S19K_NATIVE_MIN_FAN_RPM: u32 = 2_000;", "four-channel 2000 RPM floor"),
            _fact(SERIAL_SOURCE, serial, "S19kNativeCoolingStage::PostResetRelease", "post-reset cooling recapture"),
        ],
        "watchdog": [
            _fact(SERIAL_SOURCE, serial, "pub(super) fn claim_s19k_native(watchdog: &mut SafetyWatchdogOwner)", "native watchdog route"),
        ],
        "rollback": [
            _fact(SERIAL_SOURCE, serial, "fn first_stage_safe_off(&self)", "reset-before-cut early SafeOff"),
            _fact(SERIAL_SOURCE, serial, "impl Drop for NoPicPsuGuard", "drop-time reset and cut"),
        ],
        "terminal_safe_off": [
            _fact(SERIAL_SOURCE, serial, "static S19K_NATIVE_TEARDOWN_ARMED", "dedicated native panic state"),
            _fact(SERIAL_SOURCE, serial, "fn safe_off(\n        &mut self,", "checked terminal SafeOff owner"),
        ],
    }


def audit_source_corpus(corpus: Mapping[str, bytes]) -> dict[str, Any]:
    if set(corpus) != set(SOURCE_PATHS):
        fail(f"source corpus keys are not exact: {sorted(corpus)}")
    text = {path: _decode(corpus[path], path) for path in SOURCE_PATHS}
    policy, hal, serial = text[POLICY_SOURCE], text[HAL_SOURCE], text[SERIAL_SOURCE]
    _require_all(
        policy,
        (
            'pub const S19K_AM3_BOARD_TARGET: &str = "am3-s19k";',
            "pub const S19K_BM1366_ASIC_NUM: u16 = 77;",
            "pub const S19K_GPIO_PWR_EN: u32 = 437;",
            "S19K_AM3_GPIO437_VALUE_OFF",
        ),
        "S19k policy",
    )
    _require_all(
        text[RUST_TOOLCHAIN_SOURCE],
        ('channel = "1.90.0"', '"aarch64-unknown-linux-musl"'),
        "pinned Rust toolchain",
    )
    _require_all(
        text[CARGO_CONFIG_SOURCE],
        (
            "[target.aarch64-unknown-linux-musl]",
            'linker = "rust-lld"',
            '"-C", "target-cpu=cortex-a53"',
            '"-C", "target-feature=+crt-static"',
        ),
        "AArch64 cargo target",
    )
    _require_all(
        text[ZIG_CC_SOURCE],
        (
            'zig_bin="${ZIG_EXE:-}"',
            "exec \"$zig_bin\" cc -target aarch64-linux-musl -mcpu=cortex_a53",
        ),
        "AArch64 Zig C wrapper",
    )
    _require_all(
        text[ZIG_AR_SOURCE],
        ('zig_bin="${ZIG_EXE:-}"', 'exec "$zig_bin" ar "$@"'),
        "AArch64 Zig archiver wrapper",
    )
    _require_all(
        text[AARCH64_CHECK_SOURCE],
        (
            "readonly TARGET=aarch64-unknown-linux-musl",
            "readonly EXPECTED_ZIG_VERSION=0.13.0",
            "readonly EXPECTED_ZIG_SHA256="
            "7f9e3a661e909d5188d1b8b14f082b98a19c323a30d43bfdd1b2893ed37273e0",
            "export CARGO_NET_OFFLINE=true",
            'cargo check --offline --locked --target "$TARGET"',
            "-p dcentrald-common -p dcentrald-hal -p dcentrald",
            'cargo build --offline --locked --release --target "$TARGET"',
            "-p dcentrald --bin dcentrald",
            "S19K_AARCH64_RELEASE_LINK_SMOKE_OK",
            "authority=none capsule_required=build-dcentrald.sh_amlogic",
            "schema-v4 build",
            "immutable Git-object snapshot and complete Cargo graph",
        ),
        "S19k AArch64 compile contract",
    )
    _require_all(
        text[NATIVE_BUILD_SOURCE],
        (
            'SCHEMA = "dcentos.s19k-native-release-link-candidate/v4"',
            "exact-snapshot-capsule-linked-manifest-key-pinned-network-enabled-bootstrap-",
            '"capsule_build_receipt": capsule_copy',
            '"local_dependency_closure": closure',
            '"network_nonuse_proven": False',
            '"network_contract": NETWORK_CONTRACT',
            '"release_authority_granted": False',
            '"installation_authority_granted": False',
            "def verify_receipt(",
        ),
        "native release-link receipt verifier",
    )
    capabilities = {
        name: {"status": "joined", "evidence": []}
        for name in REQUIRED_OWNER_CAPABILITIES
    }
    native_identity = re.sub(r"\s+", " ", text[NATIVE_IDENTITY_SOURCE].split("#[cfg(test)]", 1)[0])
    _require_all(
        native_identity,
        (
            "platform.read_identity_pages(service,",
            "names[slot] = Some(decode_deployed_eeprom(page)?.board_name)",
            "platform.bind_population_polarity(service, names.each_ref().map(|name| name.as_deref()))?",
            "let identity = decode_deployed_eeprom(page)",
            "identity.region_1_crc5 == Crc5Check::Match",
            "S19kNativeBoardModel::parse(&identity.board_name)",
            "observed_protocol_from_deployed_page(page) == Some(AsicProtocolIdentity::Bm1366)",
            "page.is_some() == populated[slot]",
        ),
        "native EEPROM identity producer",
    )
    _require_all(
        serial,
        ("s19k_native_identity::capture(&mapped, &service)",),
        "native identity startup integration",
    )
    for name, facts in {**_audit_hal(hal), **_audit_serial(serial)}.items():
        capabilities[name]["evidence"].extend(facts)
    capabilities["identity"]["evidence"].insert(
        0,
        _fact(POLICY_SOURCE, policy, 'pub const S19K_AM3_BOARD_TARGET: &str = "am3-s19k";', "exact board target"),
    )
    capabilities["gpio437"]["evidence"].insert(
        0,
        _fact(POLICY_SOURCE, policy, "pub const S19K_GPIO_PWR_EN: u32 = 437;", "board-scoped GPIO437"),
    )
    capabilities["population_uart_admission"]["evidence"].append(
        _fact(SERIAL_SOURCE, serial, "Self::init_bm1366_chains(native_backends, target_freq)", "fresh identical 77-chip-per-selected-route init")
    )
    source_files = [
        {"path": path, "sha256": _sha256(corpus[path]), "bytes": len(corpus[path])}
        for path in SOURCE_PATHS
    ]
    return {
        "schema": SCHEMA,
        "phase_id": "native-cold-start-owner",
        "classification": "ready",
        "production_owner_present": True,
        "authority_minted": False,
        "host_only_source_audit": True,
        "live_hardware_contacted": False,
        "must_join_before_authority": list(REQUIRED_OWNER_CAPABILITIES),
        "source_files": source_files,
        "aarch64_compile_contract": native_build.AARCH64_COMPILE_CONTRACT,
        "capability_inventory": capabilities,
    }


def audit_source_tree(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    return audit_source_corpus(load_source_corpus(repo_root))


def _self_id(receipt: Mapping[str, Any], label: str) -> str:
    observed = receipt.get("verification_id")
    if observed is None:
        return _sha256(canonical_json(receipt))
    _hex64(observed, f"{label} verification_id")
    projected = dict(receipt)
    del projected["verification_id"]
    expected = _sha256(canonical_json(projected))
    if observed != expected:
        fail(f"{label} verification_id does not match canonical contents")
    return observed


def _prerequisite_ids(
    evidence_dir: Path,
) -> tuple[dict[str, str], dict[str, Any]]:
    parent = evidence_dir.parent
    re_receipt = _json(
        _read_regular(
            parent.joinpath(*PREREQUISITE_PATHS["native-secure-firmware-re"]),
            MAX_JSON_BYTES,
            "native secure-firmware RE receipt",
        ),
        "native secure-firmware RE receipt",
    )
    if (
        re_receipt.get("schema") != NATIVE_RE_SCHEMA
        or re_receipt.get("classification") != "runtime-secure-sram-key-boundary"
        or re_receipt.get("live_contact_authorized") is not False
    ):
        fail("native secure-firmware RE receipt has an unsafe classification")
    hardware = _json(
        _read_regular(
            parent.joinpath(*PREREQUISITE_PATHS["native-hardware-contract"]),
            MAX_JSON_BYTES,
            "native hardware receipt",
        ),
        "native hardware receipt",
    )
    if (
        hardware.get("schema") != NATIVE_HARDWARE_SCHEMA
        or hardware.get("claim") != "reviewed-common-clock-native-hardware-contract"
        or hardware.get("authority_granted") is not False
        or hardware.get("tty_to_physical_address") != {"/dev/ttyS1": 3, "/dev/ttyS2": 2}
        or hardware.get("reset_gpio_to_tty") != {"455": "/dev/ttyS2", "456": "/dev/ttyS1"}
        or hardware.get("gpio437_raw_energized") != 0
        or hardware.get("gpio437_raw_safeoff") != 1
    ):
        fail("native hardware receipt does not bind reviewed mapping/polarity")
    endurance_data = _read_regular(
        parent.joinpath(*PREREQUISITE_PATHS["adopted-endurance"]),
        MAX_JSON_BYTES,
        "adopted endurance host receipt",
    )
    try:
        endurance_lines = endurance_data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        fail(f"adopted endurance host receipt is not ASCII: {error}")
    if (
        not endurance_lines
        or endurance_lines[0] != f"schema={ENDURANCE_SCHEMA}"
        or "outcome=pass" not in endurance_lines
    ):
        fail("adopted endurance host receipt is not the passing contract")
    keys = [line.split("=", 1)[0] for line in endurance_lines if "=" in line]
    if len(keys) != len(endurance_lines) or len(keys) != len(set(keys)):
        fail("adopted endurance host receipt has malformed/duplicate fields")
    reproducibility = _json(
        _read_regular(
            parent.joinpath(*PREREQUISITE_PATHS["native-build-reproducibility"]),
            MAX_JSON_BYTES,
            "native build reproducibility receipt",
        ),
        "native build reproducibility receipt",
    )
    artifact = reproducibility.get("artifact")
    observations = reproducibility.get("observations")
    equality = reproducibility.get("equality")
    if (
        reproducibility.get("schema") != REPRODUCIBILITY_SCHEMA
        or reproducibility.get("classification")
        != "two-distinct-sealed-capsule-results-byte-identical"
        or reproducibility.get("two_capsule_byte_reproducibility_observed")
        is not True
        or reproducibility.get("build_causality_proven") is not False
        or reproducibility.get("independent_compiler_execution_proven") is not False
        or reproducibility.get("release_authority_granted") is not False
        or reproducibility.get("installation_authority_granted") is not False
        or reproducibility.get("live_hardware_contacted") is not False
        or reproducibility.get("persistent_mutation_authority_granted") is not False
        or not isinstance(artifact, dict)
        or set(artifact) != {
            "path", "sha256", "bytes", "elf_class", "machine"
        }
        or artifact.get("path") != "dcentrald"
        or artifact.get("elf_class") != 64
        or artifact.get("machine") != 183
        or not isinstance(observations, list)
        or len(observations) != 2
        or not isinstance(equality, dict)
        or not all(value is True for value in equality.values())
    ):
        fail("native build reproducibility receipt is not the bounded v3 contract")
    invocation_ids = {
        item.get("release_invocation_id")
        for item in observations
        if isinstance(item, dict)
    }
    native_build_ids = {
        item.get("native_build_verification_id")
        for item in observations
        if isinstance(item, dict)
    }
    if (
        len(invocation_ids) != 2
        or len(native_build_ids) != 2
        or any(not isinstance(value, str) for value in invocation_ids | native_build_ids)
    ):
        fail("native build reproducibility observations are not independent")
    ids = {
        "native-secure-firmware-re": _self_id(re_receipt, "native RE"),
        "native-hardware-contract": _self_id(hardware, "native hardware"),
        "adopted-endurance": _sha256(endurance_data),
        "native-build-reproducibility": _self_id(
            reproducibility, "native build reproducibility"
        ),
    }
    return ids, reproducibility


def _verify_artifact(data: bytes) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        fail("native owner artifact is not ELF")
    if data[4] != 2 or data[5] != 1:
        fail("native owner artifact must be little-endian ELF64")
    file_type, machine = struct.unpack_from("<HH", data, 16)
    if file_type not in (2, 3) or machine != 183:
        fail("native owner artifact is not an AArch64 executable/shared executable")


def expected_inputs(
    prerequisite_ids: Mapping[str, str],
    artifact: bytes,
    source: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
    reproducibility: Mapping[str, Any],
) -> dict[str, Any]:
    artifact_sha256 = _sha256(artifact)
    if artifact_sha256 in ADOPTED_ROUTE_ARTIFACT_SHA256S:
        fail("native owner artifact reuses an older adopted-route binary")
    capsule = build_receipt["capsule_build_receipt"]
    lineage = capsule["release_capsule"]
    observations = reproducibility["observations"]
    native_build_ids = sorted(
        item["native_build_verification_id"] for item in observations
    )
    invocation_ids = sorted(
        item["release_invocation_id"] for item in observations
    )
    if (
        reproducibility["artifact"]["sha256"] != artifact_sha256
        or reproducibility["artifact"]["bytes"] != len(artifact)
        or build_receipt["verification_id"] not in native_build_ids
        or lineage["release_invocation_id"] not in invocation_ids
        or reproducibility.get("source", {}).get("commit_oid")
        != capsule["git"]["commit"]
        or reproducibility.get("source", {}).get("source_snapshot_id")
        != lineage["source_snapshot_id"]
        or reproducibility.get("input_contract", {}).get(
            "manifest_public_key_hex"
        )
        != build_receipt.get("manifest_public_key_hex")
        or reproducibility.get("input_contract", {}).get(
            "manifest_public_key_sha256"
        )
        != build_receipt.get("manifest_public_key_sha256")
    ):
        fail("native owner artifact is outside the reproducibility observation")
    return {
        "schema": INPUT_SCHEMA,
        "prerequisite_verification_ids": dict(prerequisite_ids),
        "native_owner_artifact": {
            "path": ARTIFACT_NAME,
            "sha256": artifact_sha256,
            "bytes": len(artifact),
            "target_triple": "aarch64-unknown-linux-musl",
            "cargo_profile": "release",
            "artifact_role": "native-cold-start-owner",
            "source_files_sha256": _sha256(canonical_json(source["source_files"])),
            "compile_contract_sha256": _sha256(
                canonical_json(source["aarch64_compile_contract"])
            ),
            "native_build_verification_id": build_receipt["verification_id"],
            "capsule_build_receipt_sha256": build_receipt[
                "capsule_build_receipt_sha256"
            ],
            "source_commit": capsule["git"]["commit"],
            "source_snapshot_id": lineage["source_snapshot_id"],
            "release_invocation_id": lineage["release_invocation_id"],
            "cargo_metadata_sha256": build_receipt["local_dependency_closure"][
                "cargo_metadata_sha256"
            ],
            "manifest_public_key_hex": build_receipt[
                "manifest_public_key_hex"
            ],
            "manifest_public_key_sha256": build_receipt[
                "manifest_public_key_sha256"
            ],
            "native_reproducibility_verification_id": prerequisite_ids[
                "native-build-reproducibility"
            ],
            "observed_native_build_verification_ids": native_build_ids,
            "observed_release_invocation_ids": invocation_ids,
        },
    }


def _inputs(
    evidence_dir: Path,
    prerequisite_ids: Mapping[str, str],
    artifact: bytes,
    source: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
    reproducibility: Mapping[str, Any],
) -> dict[str, Any]:
    value = _json(
        _read_regular(evidence_dir / INPUT_NAME, MAX_JSON_BYTES, INPUT_NAME), INPUT_NAME
    )
    expected = expected_inputs(
        prerequisite_ids, artifact, source, build_receipt, reproducibility
    )
    if value != expected:
        fail("inputs.json does not bind the exact source-built dcentrald artifact")
    return value


def build_result(evidence_dir: Path, *, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"owner evidence directory is absent or unsafe: {evidence_dir}")
    source = audit_source_tree(repo_root)
    prerequisite_ids, reproducibility = _prerequisite_ids(evidence_dir)
    artifact = _read_regular(
        evidence_dir / ARTIFACT_NAME, MAX_ARTIFACT_BYTES, "native owner artifact"
    )
    _verify_artifact(artifact)
    build_receipt = native_build.verify_receipt(
        evidence_dir / BUILD_RECEIPT_NAME,
        evidence_dir / ARTIFACT_NAME,
        source=source,
        repo_root=repo_root,
    )
    inputs = _inputs(
        evidence_dir,
        prerequisite_ids,
        artifact,
        source,
        build_receipt,
        reproducibility,
    )
    source_files_sha256 = _sha256(canonical_json(source["source_files"]))
    compile_contract_sha256 = _sha256(
        canonical_json(source["aarch64_compile_contract"])
    )
    capsule = build_receipt["capsule_build_receipt"]
    lineage = capsule["release_capsule"]
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "phase_id": "native-cold-start-owner",
        "classification": "verified",
        "source_readiness_classification": "ready",
        "production_owner_present": True,
        "dependency_evidence_bound": True,
        "prerequisite_verification_ids": prerequisite_ids,
        "native_owner_artifact": {
            "path": "usr/local/bin/dcentrald",
            "sha256": _sha256(artifact),
            "bytes": len(artifact),
        },
        "native_owner_build_binding": {
            "target_triple": "aarch64-unknown-linux-musl",
            "cargo_profile": "release",
            "artifact_role": "native-cold-start-owner",
            "source_files_sha256": source_files_sha256,
            "compile_contract_sha256": compile_contract_sha256,
            "adopted_artifact_reused": False,
            "native_build_verification_id": build_receipt["verification_id"],
            "capsule_build_receipt_sha256": build_receipt[
                "capsule_build_receipt_sha256"
            ],
            "source_commit": capsule["git"]["commit"],
            "source_snapshot_id": lineage["source_snapshot_id"],
            "release_invocation_id": lineage["release_invocation_id"],
            "cargo_metadata_sha256": build_receipt["local_dependency_closure"][
                "cargo_metadata_sha256"
            ],
            "manifest_public_key_hex": build_receipt[
                "manifest_public_key_hex"
            ],
            "manifest_public_key_sha256": build_receipt[
                "manifest_public_key_sha256"
            ],
            "native_reproducibility_verification_id": prerequisite_ids[
                "native-build-reproducibility"
            ],
            "observed_native_build_verification_ids": sorted(
                item["native_build_verification_id"]
                for item in reproducibility["observations"]
            ),
            "observed_release_invocation_ids": sorted(
                item["release_invocation_id"]
                for item in reproducibility["observations"]
            ),
        },
        "native_build_receipt": build_receipt,
        "source_files": source["source_files"],
        "aarch64_compile_contract": source["aarch64_compile_contract"],
        "capability_inventory": source["capability_inventory"],
        "inputs_sha256": _sha256(canonical_json(inputs)),
        "host_only_source_audit": True,
        "live_hardware_contacted": False,
        "authority_minted": False,
    }
    result["verification_id"] = _sha256(canonical_json(result))
    return result


def verify_implementation_receipt(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"owner evidence directory is absent or unsafe: {evidence_dir}")
    observed_names = {entry.name for entry in evidence_dir.iterdir()}
    if observed_names != set(PHASE_FILES):
        fail(
            "native owner phase file set is not exact: "
            f"expected={sorted(PHASE_FILES)} observed={sorted(observed_names)}"
        )
    result = build_result(evidence_dir, repo_root=repo_root)
    receipt = _read_regular(
        evidence_dir / RECEIPT_NAME, MAX_JSON_BYTES, "native owner receipt"
    )
    if receipt != canonical_json(result):
        fail("verification.json is stale, noncanonical, or not freshly reproducible")
    return result


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    return verify_implementation_receipt(evidence_dir)


def prepare_inputs(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"owner evidence directory is absent or unsafe: {evidence_dir}")
    observed = {entry.name for entry in evidence_dir.iterdir()}
    if observed not in (
        {ARTIFACT_NAME, BUILD_RECEIPT_NAME},
        {INPUT_NAME, ARTIFACT_NAME, BUILD_RECEIPT_NAME},
    ):
        fail(f"refusing unsafe owner input-preparation file set: {sorted(observed)}")
    source = audit_source_tree(repo_root)
    prerequisite_ids, reproducibility = _prerequisite_ids(evidence_dir)
    artifact = _read_regular(
        evidence_dir / ARTIFACT_NAME, MAX_ARTIFACT_BYTES, "native owner artifact"
    )
    _verify_artifact(artifact)
    build_receipt = native_build.verify_receipt(
        evidence_dir / BUILD_RECEIPT_NAME,
        evidence_dir / ARTIFACT_NAME,
        source=source,
        repo_root=repo_root,
    )
    value = expected_inputs(
        prerequisite_ids, artifact, source, build_receipt, reproducibility
    )
    expected = canonical_json(value)
    destination = evidence_dir / INPUT_NAME
    if destination.exists():
        if _read_regular(destination, MAX_JSON_BYTES, INPUT_NAME) != expected:
            fail(f"refusing to overwrite stale {INPUT_NAME}: {destination}")
    else:
        with destination.open("xb") as handle:
            handle.write(expected)
    return value


def stage_implementation_receipt(
    evidence_dir: Path, *, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"owner evidence directory is absent or unsafe: {evidence_dir}")
    observed = {entry.name for entry in evidence_dir.iterdir()}
    if observed not in (
        {INPUT_NAME, ARTIFACT_NAME, BUILD_RECEIPT_NAME},
        set(PHASE_FILES),
    ):
        fail(f"refusing unsafe owner phase file set: {sorted(observed)}")
    result = build_result(evidence_dir, repo_root=repo_root)
    destination = evidence_dir / RECEIPT_NAME
    expected = canonical_json(result)
    if destination.exists():
        if _read_regular(destination, MAX_JSON_BYTES, RECEIPT_NAME) != expected:
            fail(f"refusing to overwrite stale receipt: {destination}")
    else:
        with destination.open("xb") as handle:
            handle.write(expected)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "audit",
            "prepare-inputs",
            "stage-implementation-receipt",
            "verify",
        ),
    )
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            result = audit_source_tree()
        elif args.command == "prepare-inputs":
            result = prepare_inputs(args.evidence_dir.resolve())
        elif args.command == "stage-implementation-receipt":
            result = stage_implementation_receipt(args.evidence_dir.resolve())
        else:
            result = verify_implementation_receipt(args.evidence_dir.resolve())
    except (OSError, NativeOwnerError, native_build.NativeBuildError) as error:
        print(f"S19K_NATIVE_OWNER_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
