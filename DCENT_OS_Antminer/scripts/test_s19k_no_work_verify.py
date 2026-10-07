#!/usr/bin/env python3
"""Adversarial tests for the S19k joined Phase-1/Phase-2 verifier."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_no_work_verify as verifier  # noqa: E402
import s19k_phase12_capture_verify as raw_capture  # noqa: E402
import s19k_phase12_normalize as normalizer  # noqa: E402


PREPARER_PATH = SCRIPT_DIR / verifier.PREPARER_FILENAME
NORMALIZER_PATH = SCRIPT_DIR / verifier.NORMALIZER_FILENAME
CAPTURE_VERIFIER_PATH = Path(raw_capture.__file__)


ARTIFACT_DATA = b"fixture-armv7-dcentrald\n"
CONFIG_DATA = b'[platform]\ntarget = "am3-aml-s19k"\n[thermal]\ndangerous_temp_c = 80\n'
RUNNER_DATA = b"#!/bin/sh\n# fixture runner\n"
CUSTODY_DATA = b"#!/bin/sh\n# fixture custody observer\n"
STOCK_HELPER_DATA = b"#!/bin/sh\n# fixture stock restart helper\n"
ARTIFACT_SHA = hashlib.sha256(ARTIFACT_DATA).hexdigest()
CONFIG_SHA = hashlib.sha256(CONFIG_DATA).hexdigest()
RUNNER_SHA = hashlib.sha256(RUNNER_DATA).hexdigest()
CUSTODY_SHA = hashlib.sha256(CUSTODY_DATA).hexdigest()
STOCK_HELPER_SHA = hashlib.sha256(STOCK_HELPER_DATA).hexdigest()
LIVE_SHA = "f" * 64
MODEL_SHA = "1" * 64
TRANSACTION = "2" * 64
J0_SHA = "3" * 64
REMOTE = "/tmp/dcentrald_bench_t1_fixture"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kv_bytes(fields: list[tuple[str, str]]) -> bytes:
    return ("".join(f"{key}={value}\n" for key, value in fields)).encode("utf-8")


def artifact_fields() -> list[tuple[str, str]]:
    return [
        ("binary_sha256", ARTIFACT_SHA),
        ("binary_bytes", str(len(ARTIFACT_DATA))),
        ("config_sha256", CONFIG_SHA),
        ("config_bytes", str(len(CONFIG_DATA))),
        ("runner_sha256", RUNNER_SHA),
        ("runner_bytes", str(len(RUNNER_DATA))),
        ("custody_observer_sha256", CUSTODY_SHA),
        ("custody_observer_bytes", str(len(CUSTODY_DATA))),
        ("stock_restart_helper_sha256", STOCK_HELPER_SHA),
        ("stock_restart_helper_bytes", str(len(STOCK_HELPER_DATA))),
    ]


def identity_fields() -> list[tuple[str, str]]:
    return [
        ("live_identity_schema", verifier.LIVE_IDENTITY_SCHEMA),
        ("live_identity_profile", verifier.LIVE88_PROFILE),
        ("live_identity_sha256", LIVE_SHA),
        ("live_identity_model_sha256", MODEL_SHA),
    ]


def transcript_text() -> str:
    return (
        "\n".join(
            [
                f"INFO dcentrald::serial_mining: j3_frozen_tids=8 live_identity_sha256={LIVE_SHA} live_identity_model_sha256={MODEL_SHA} live_identity_profile={verifier.LIVE88_PROFILE} {verifier.J3_HANDOFF_MARKER}",
                f'INFO dcentrald::serial_mining: path="/dev/ttyS1" frames=77 rx="fixture" enum_st=Complete77 {verifier.GETADDRESS_MARKER}',
                f'INFO dcentrald::serial_mining: path="/dev/ttyS2" frames=77 rx="fixture" enum_st=Complete77 {verifier.GETADDRESS_MARKER}',
                f'INFO dcentrald::serial_mining: path="/dev/ttyS3" frames=0 rx="silence" enum_st=Silence {verifier.GETADDRESS_MARKER}',
                f"INFO dcentrald::serial_mining: seated=2 hottest=Some(61.0) spinning_fans=4 {verifier.THERMAL_READY_MARKER}",
                f'INFO dcentrald::serial_mining: work_authority="disabled" dispatch_admitted=false actor_tx_guard=true {verifier.NO_WORK_MARKER}',
                f'INFO dcentrald::serial_mining: job_id="fixture-job" no_work_jobs_discarded=1 work_authority="disabled" {verifier.DISCARDED_JOB_MARKER}',
                "INFO dcentrald::serial_mining: Track-1 terminal GPIO437 SafeOff completed after reset attempts",
            ]
        )
        + "\n"
    )


def instrument_csv() -> bytes:
    header = ",".join(verifier.INSTRUMENT_HEADER)
    rows: list[str] = []
    for timestamp in range(0, 15_000, 1_000):
        event = "run-start" if timestamp == 3_000 else "sample"
        if timestamp < 4_000:
            gpios = (0, 0, 1, 1)
        elif timestamp < 5_000:
            gpios = (0, 0, 0, 0)
        else:
            gpios = (1, 0, 0, 0)
        rail = {
            0: 14_000,
            1_000: 14_050,
            2_000: 13_950,
            3_000: 14_000,
            4_000: 13_900,
            5_000: 12_000,
            6_000: 7_000,
            7_000: 2_000,
            8_000: 600,
        }.get(timestamp, 300)
        values = [
            str(timestamp),
            event,
            str(rail),
            "3050",
            "3040",
            "3030",
            "3020",
            "55000",
            "61000",
            "54000",
            "60000",
            *(str(value) for value in gpios),
        ]
        rows.append(",".join(values))
    return (header + "\n" + "\n".join(rows) + "\n").encode("utf-8")


def uart_csv() -> bytes:
    header = ",".join(verifier.UART_HEADER)
    rows = [
        "3200,/dev/ttyS1,tx,55AA510900280000301112",
        "3300,/dev/ttyS1,rx,AA55010203040506070809",
        "3400,/dev/ttyS2,tx,55AA510900280000301112",
        "3500,/dev/ttyS2,rx,AA55010203040506070809",
        "3600,/dev/ttyS3,tx,55AA510900280000301112",
    ]
    return (header + "\n" + "\n".join(rows) + "\n").encode("utf-8")


def raw_capture_files(clock: str) -> tuple[bytes, bytes]:
    contract = {
        "schema": raw_capture.CONTRACT_SCHEMA,
        "common_clock_id": clock,
        "window_start_ns": 0,
        "window_end_ns": 15_000_000_000,
        "rail_signal": "rail-millivolts",
        "populated_uart_paths": ["/dev/ttyS1", "/dev/ttyS2"],
    }
    instrument_rows = instrument_csv().decode("ascii").splitlines()[1:]
    rail_points = {
        int(row.split(",")[0]): int(row.split(",")[2])
        for row in instrument_rows
    }
    rail_values: list[int] = []
    current_rail = rail_points[0]
    for timestamp_ms in range(15_000):
        current_rail = rail_points.get(timestamp_ms, current_rail)
        rail_values.append(current_rail)
    rail_payload = b"".join(
        value.to_bytes(2, "little") for value in rail_values
    ).hex()
    rows = [",".join(raw_capture.HEADER)]
    for channel in raw_capture._required_channels(
        contract["populated_uart_paths"]
    ):
        channel_class = raw_capture._channel_class(channel)
        period = raw_capture.PERIOD_LIMIT_NS[channel_class]
        count = contract["window_end_ns"] // period
        if channel_class == "rail":
            encoding = "u16le"
            payload = rail_payload
        else:
            encoding = "rle-bit-v1"
            payload = (b"\x00" + count.to_bytes(4, "little")).hex()
        rows.append(
            ",".join(
                (
                    clock,
                    "0",
                    channel,
                    "0",
                    str(period),
                    str(count),
                    encoding,
                    payload,
                )
            )
        )
    return raw_capture.canonical_json(contract), ("\n".join(rows) + "\n").encode(
        "ascii"
    )


def normalization_config_data() -> bytes:
    scaled = lambda column: {  # noqa: E731
        "add": 0,
        "column": column,
        "divide": 1,
        "kind": "scaled-decimal",
        "multiply": 1,
    }
    instrument_fields = {
        field: scaled(field) for field in verifier.INSTRUMENT_HEADER[2:]
    }
    instrument_fields["event"] = {
        "column": "event",
        "kind": "enum",
        "values": {"run-start": "run-start", "sample": "sample"},
    }
    config = {
        "schema": normalizer.CONFIG_SCHEMA,
        "common_clock_id": "scope-logic-common-clock-001",
        "rail_signal": "rail-millivolts",
        "instrument": {
            "delimiter": ",",
            "trim_whitespace": False,
            "timestamp": {
                "column": "monotonic_ms",
                "unit": "ms",
                "offset_ms": 0,
                "rounding": "exact",
            },
            "fields": instrument_fields,
        },
        "uart": {
            "delimiter": ",",
            "trim_whitespace": False,
            "timestamp": {
                "column": "monotonic_ms",
                "unit": "ms",
                "offset_ms": 0,
                "rounding": "exact",
            },
            "fields": {
                "path": {
                    "column": "path",
                    "kind": "enum",
                    "values": {
                        path: path
                        for path in verifier.REQUIRED_PATHS + verifier.OPTIONAL_PATHS
                    },
                },
                "direction": {
                    "column": "direction",
                    "kind": "enum",
                    "values": {"rx": "rx", "tx": "tx"},
                },
                "frame_hex": {"column": "frame_hex", "kind": "hex-bytes"},
            },
        },
    }
    return (
        json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def preflight_data() -> bytes:
    values = {
        "schema": verifier.PREFLIGHT_SCHEMA,
        "authorization_reference": "office-run-20260822-001",
        "authorized_utc": "2026-08-22T11:30:00Z",
        "ssh_host_key_sha256": "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg",
        "authorized_miner_identity_sha256": LIVE_SHA,
        "hardware_reviewer": "dcentral-ee-reviewer-01",
        "board_revision": "BHB56903-revision-reviewed",
        "test_point_id": "BHB56903-main-rail-TP-reviewed",
        "test_point_reference_node": "BHB56903-reviewed-rail-return",
        "test_point_approval": "hardware-reviewer-approved-deenergized",
        "rail_coverage": "slots2-and3-only-populated-hashboard-feeds",
        "rail_slot2_location": "slot2-BHB56903-reviewed-rail-point",
        "rail_slot3_location": "slot3-BHB56903-reviewed-rail-point",
        "rail_slot2_reference_or_conductor": "slot2-reviewed-rail-return",
        "rail_slot3_reference_or_conductor": "slot3-reviewed-rail-return",
        "rail_capture_topology": "two-isolated-slot-voltage-channels",
        "rail_composite_rule": "maximum-of-slot2-and-slot3-magnitude",
        "measurement_method": "isolated-differential-voltage",
        "expected_range_min": "0",
        "expected_range_max": "15000",
        "expected_range_unit": "millivolts",
        "instrument_identity": "isolated-recorder-model-fixture-serial-001",
        "instrument_voltage_rating_millivolts": "30000",
        "instrument_current_rating_milliamps": "0",
        "instrument_cat_rating": "CAT-III-600V",
        "instrument_isolation": "isolated-differential",
        "lead_insulation_status": "inspected-intact",
        "fuse_status": "verified-serviceable-or-not-applicable-reviewed",
        "calibration_status": "in-calibration-and-zero-checked",
        "calibration_due_utc": "2027-08-22T00:00:00Z",
        "rail_slot2_channel": "scope-CH1",
        "rail_slot3_channel": "scope-CH2",
        "rail_polarity": "positive-is-energized",
        "gpio437_channel": "logic-D0",
        "gpio437_test_point": "am3-s19k-gpio437-reviewed-pad",
        "gpio437_polarity": "raw0-energized-raw1-safeoff",
        "gpio454_channel": "logic-D1",
        "gpio454_test_point": "am3-s19k-gpio454-reviewed-pad",
        "gpio454_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio455_channel": "logic-D2",
        "gpio455_test_point": "am3-s19k-gpio455-reviewed-pad",
        "gpio455_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio456_channel": "logic-D3",
        "gpio456_test_point": "am3-s19k-gpio456-reviewed-pad",
        "gpio456_polarity": "raw1-reset-released-raw0-reset-asserted",
        "gpio_reference_node": "am3-s19k-reviewed-logic-reference",
        "gpio_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "gpio_expected_max_millivolts": "5000",
        "gpio_input_rating_millivolts": "25000",
        "gpio_input_impedance_ohms": "1000000",
        "gpio_logic_threshold_approval": "hardware-reviewer-approved-for-observed-levels",
        "gpio_edge_clock": "common-clock-native-single-acquisition",
        "gpio_edge_sample_rate_hz": "100000",
        "gpio_edge_resolution_us": "10",
        "fan0_tach_channel": "logic-D4",
        "fan0_tach_test_point": "fan0-reviewed-tach-point",
        "fan1_tach_channel": "logic-D5",
        "fan1_tach_test_point": "fan1-reviewed-tach-point",
        "fan2_tach_channel": "logic-D6",
        "fan2_tach_test_point": "fan2-reviewed-tach-point",
        "fan3_tach_channel": "logic-D7",
        "fan3_tach_test_point": "fan3-reviewed-tach-point",
        "fan_tach_reference_node": "am3-s19k-reviewed-logic-reference",
        "fan_tach_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "fan_tach_expected_max_millivolts": "5000",
        "fan_tach_input_rating_millivolts": "25000",
        "fan_tach_input_impedance_ohms": "1000000",
        "fan_tach_sample_rate_hz": "10000",
        "fan_harness_status": "untouched-fans-remain-connected",
        "temperature_channels": "logger-slot2-slot3-inlet-outlet",
        "ttys1_rx_channel": "logic-D8",
        "ttys1_rx_test_point": "ttyS1-reviewed-rx-point",
        "ttys1_tx_channel": "logic-D9",
        "ttys1_tx_test_point": "ttyS1-reviewed-tx-point",
        "ttys2_rx_channel": "logic-D10",
        "ttys2_rx_test_point": "ttyS2-reviewed-rx-point",
        "ttys2_tx_channel": "logic-D11",
        "ttys2_tx_test_point": "ttyS2-reviewed-tx-point",
        "ttys3_rx_channel": "logic-D12",
        "ttys3_rx_test_point": "ttyS3-reviewed-rx-point",
        "ttys3_tx_channel": "logic-D13",
        "ttys3_tx_test_point": "ttyS3-reviewed-tx-point",
        "uart_reference_node": "am3-s19k-reviewed-logic-reference",
        "uart_probe_interface": "isolated-high-impedance-receive-only-no-pull-no-drive",
        "uart_expected_max_millivolts": "5000",
        "uart_input_rating_millivolts": "25000",
        "uart_input_impedance_ohms": "1000000",
        "uart_line_contract": "passive-8n1-noninverting-no-transmit",
        "uart_max_baud": "3125000",
        "uart_sample_rate_hz": "25000000",
        "wall_power_channel": "isolated-meter-power",
        "common_clock_id": "scope-logic-common-clock-001",
        "clock_sync_method": "recorded-common-clock-edge",
        "clock_sync_event_id": "sync-edge-before-run-001",
        "clock_skew_max_ms": "1",
        "timestamp_unit": "milliseconds",
        "timestamp_rounding": "exact-or-conservative-floor",
        "slow_monitor_sample_rate_millihz": "1000",
        "recording_advancing_proof": "two-distinct-pre-run-samples-observed",
        "emergency_responder": "office-responder-01",
        "disconnect_path": "reachable-ac-input-disconnect",
        "disconnect_tested_utc": "2026-08-22T11:20:00Z",
        "disconnect_test_status": "proven-deenergized-before-probe-attachment",
        "operator_ack": "abort-on-rebound-cooling-loss-clock-loss-or-probe-movement",
        "publication": "pre-energization-reviewed-record",
    }
    return kv_bytes([(key, values[key]) for key in verifier.PREFLIGHT_KEYS])


def verify_preflight_only(data: bytes, rail_signal: str = "rail-millivolts") -> dict[str, object]:
    return verifier._verify_preflight(
        data,
        plan={
            "ssh_host_key_sha256": "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg"
        },
        manifest={
            "common_clock_id": "scope-logic-common-clock-001",
            "rail_signal": rail_signal,
            "created_utc": "2026-08-22T12:00:00Z",
        },
        expected_live_identity_sha256=LIVE_SHA,
    )


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.trial = root / "copied-trial"
        self.evidence = root / "instrument-evidence"
        self.trial.mkdir()
        self.evidence.mkdir()
        self.plan = root / "live.plan"
        self.transcript_name = ".startup_daemon_transcript.100.200"
        self.transcript = self.trial / self.transcript_name
        self.source = self.trial / "runtime_active_pre_safeoff"
        self.pending = self.trial / "runtime_active"
        self.terminal = self.trial / "runtime_terminal_safeoff"
        self.safeoff = self.trial / "runtime_safeoff_terminal_receipt"
        self.c1 = self.trial / "runtime_startup_c1_child_identity"
        self.j1 = self.trial / "runtime_startup_j1_daemon_blocked"
        self.j2 = self.trial / "runtime_startup_j2_child_bound"
        self.release = self.trial / "runtime_startup_release"
        self.receipt = self.trial / "runtime_handoff_no_work_transcript"
        self.manifest = self.evidence / "phase12_instrument_manifest"
        self.preflight = self.evidence / verifier.EVIDENCE_FILENAMES["preflight"]
        self.normalization_config = self.evidence / "normalization_config.json"
        self.normalization_receipt = self.evidence / normalizer.RECEIPT_OUTPUT
        self.instrument_source = self.evidence / "instrument_source.raw"
        self.instrument_canonical = self.evidence / "instrument.csv"
        self.uart_source = self.evidence / "uart_source.raw"
        self.uart_canonical = self.evidence / "uart.csv"
        self.capture_contract = self.evidence / raw_capture.CONTRACT_NAME
        self.capture_blocks = self.evidence / raw_capture.BLOCKS_NAME
        self.capture_verification = self.evidence / raw_capture.RECEIPT_NAME
        for filename, data in (
            ("dcentrald", ARTIFACT_DATA),
            ("dcentrald_s19k.toml", CONFIG_DATA),
            ("run_trial", RUNNER_DATA),
            ("supervisor_custody_observer", CUSTODY_DATA),
            ("stock_restart_helper", STOCK_HELPER_DATA),
        ):
            (self.trial / filename).write_bytes(data)
        self.transcript.write_text(transcript_text(), encoding="utf-8", newline="")
        self._write_plan()
        self._write_bound_records()
        self._write_startup_chain()
        self.write_receipt()
        self.preflight.write_bytes(preflight_data())
        self.normalization_config.write_bytes(normalization_config_data())
        self.instrument_source.write_bytes(instrument_csv())
        self.uart_source.write_bytes(uart_csv())
        contract_data, blocks_data = raw_capture_files(
            "scope-logic-common-clock-001"
        )
        self.capture_contract.write_bytes(contract_data)
        self.capture_blocks.write_bytes(blocks_data)
        self.capture_verification.write_bytes(
            raw_capture.canonical_json(
                raw_capture.build_result(
                    self.capture_contract,
                    self.capture_blocks,
                )
            )
        )
        derived = normalizer._derive_files(
            self.normalization_config,
            self.instrument_source,
            self.uart_source,
            self.instrument_canonical,
            self.uart_canonical,
        )
        self.write_normalization_receipt(derived)
        self.write_manifest()
        self.write_bundle()

    def _write_plan(self) -> None:
        fields = [
            ("schema", verifier.PLAN_SCHEMA),
            ("sha256", ARTIFACT_SHA),
            ("bytes", str(len(ARTIFACT_DATA))),
            ("operator_artifact_pin", "required-and-matched"),
            ("expected_artifact_sha256", ARTIFACT_SHA),
            ("expected_artifact_bytes", str(len(ARTIFACT_DATA))),
            ("config_sha256", CONFIG_SHA),
            ("config_bytes", str(len(CONFIG_DATA))),
            ("runner_sha256", RUNNER_SHA),
            ("runner_bytes", str(len(RUNNER_DATA))),
            ("custody_observer_sha256", CUSTODY_SHA),
            ("custody_observer_bytes", str(len(CUSTODY_DATA))),
            ("stock_restart_helper_sha256", STOCK_HELPER_SHA),
            ("stock_restart_helper_bytes", str(len(STOCK_HELPER_DATA))),
            ("persistent_mutation", "false"),
            ("no_work_flag", "--s19k-track1-no-work"),
            ("work_authority", "disabled"),
            (
                "required_ports",
                "population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
            ),
            ("mode", "handoff-no-work"),
            ("native_bm1366", "refused"),
            ("clear_for_flash", "false"),
            ("dry_run", "false"),
            ("ssh_host_key_admission", "exact-operator-pin"),
            (
                "ssh_host_key_sha256",
                "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg",
            ),
            ("ssh_global_known_hosts", "disabled-on-contact"),
        ]
        self.plan.write_bytes(kv_bytes(fields))

    def _write_bound_records(self) -> None:
        self.source.write_bytes(
            kv_bytes(
                [
                    ("schema", verifier.SOURCE_RUNTIME_SCHEMA),
                    ("phase", "child-live-or-recovery-required"),
                    *artifact_fields(),
                    *identity_fields(),
                    ("deploy_mode", "handoff-no-work"),
                    ("persistent_mutation", "false"),
                ]
            )
        )
        self.safeoff.write_text(
            "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
            f"schema={verifier.SAFEOFF_SCHEMA} live_identity_sha256={LIVE_SHA} "
            f"live_identity_profile={verifier.LIVE88_PROFILE} "
            f"live_identity_model_sha256={MODEL_SHA} live_identity_board_count=2 "
            "live_identity_physical_addresses=2,3 live_identity_board_names=BHB56903,BHB56903 "
            "live_identity_eeprom=0x50:absent,0x51:0511,0x52:0511 "
            "resets=454:0,455:0,456:0 psu=437:1\n",
            encoding="utf-8",
            newline="",
        )
        self.terminal.write_bytes(
            kv_bytes(
                [
                    ("schema", verifier.TERMINAL_HANDOFF_SCHEMA),
                    ("disposition", "terminal-safeoff-partial-stock-owner"),
                    ("runtime_active_sha256", digest(self.source.read_bytes())),
                    ("runtime_active_bytes", str(self.source.stat().st_size)),
                    ("terminal_safeoff", "true"),
                    ("watchdog_magic_close", "true"),
                    ("watchdog_worker_joined", "true"),
                    ("resets", "454:0,455:0,456:0"),
                    ("psu", "437:1"),
                    ("inherited_rails", "true"),
                    ("supervisor_signal_attempted", "true"),
                    ("supervisor_gone", "true"),
                    ("child_signal_attempted", "true"),
                    ("child_gone", "true"),
                    ("global_stock_absence", "true"),
                    ("replacement_or_ambiguity", "false"),
                    *artifact_fields(),
                    *identity_fields(),
                    ("persistent_mutation", "false"),
                ]
            )
        )
        self.pending.write_bytes(
            kv_bytes(
                [
                    ("schema", verifier.PENDING_RUNTIME_SCHEMA),
                    ("phase", "terminal-safeoff-stock-restart-pending"),
                    ("terminal", "true"),
                    ("source_runtime_active_schema", verifier.SOURCE_RUNTIME_SCHEMA),
                    ("source_runtime_active_sha256", digest(self.source.read_bytes())),
                    ("source_runtime_active_bytes", str(self.source.stat().st_size)),
                    *artifact_fields(),
                    *identity_fields(),
                    ("safeoff_receipt_schema", verifier.SAFEOFF_SCHEMA),
                    ("safeoff_receipt_sha256", digest(self.safeoff.read_bytes())),
                    ("safeoff_receipt_bytes", str(self.safeoff.stat().st_size)),
                    (
                        "terminal_handoff_receipt_schema",
                        verifier.TERMINAL_HANDOFF_SCHEMA,
                    ),
                    (
                        "terminal_handoff_receipt_sha256",
                        digest(self.terminal.read_bytes()),
                    ),
                    (
                        "terminal_handoff_receipt_bytes",
                        str(self.terminal.stat().st_size),
                    ),
                    ("resets", "454:0,455:0,456:0"),
                    ("psu", "437:1"),
                    ("dcentrald", "absent"),
                    ("stock_supervisor", "absent"),
                    ("stock_bosminer", "absent"),
                    ("watchdog_fd", "absent"),
                    ("persistent_mutation", "false"),
                    ("next_authority", "exact-stock-restart-helper-only"),
                ]
            )
        )

    def _startup_common(
        self,
        schema: str,
        ordinal: str,
        predecessor_schema: str,
        predecessor_sha: str,
        predecessor_bytes: int,
    ) -> list[tuple[str, str]]:
        return [
            ("schema", schema),
            ("transaction_id", TRANSACTION),
            ("ordinal", ordinal),
            ("predecessor_schema", predecessor_schema),
            ("predecessor_sha256", predecessor_sha),
            ("predecessor_bytes", str(predecessor_bytes)),
        ]

    def _write_startup_chain(self) -> None:
        transcript_fields = [
            ("transcript_path", f"{REMOTE}/{self.transcript_name}"),
            ("transcript_mnt_id", "42"),
            ("transcript_inode", "4242"),
            ("transcript_mode", "0600"),
            ("transcript_uid", "0"),
            ("transcript_gid", "0"),
        ]
        safety = [
            ("watchdog_start_intent", "false"),
            ("watchdog_armed", "false"),
            ("signal_attempted", "false"),
            ("inherited_rails", "false"),
            ("route_or_uart_opened", "false"),
            ("hardware_opened", "false"),
            ("persistent_mutation", "false"),
            ("publication", "no-clobber-hard-link-after-fsync"),
        ]
        self.c1.write_bytes(
            kv_bytes(
                [
                    *self._startup_common(
                        "dcentos.s19k-startup-c1-child-identity/v1",
                        "1",
                        "dcentos.s19k-startup-j0-prefork/v1",
                        J0_SHA,
                        1234,
                    ),
                    *transcript_fields,
                    *safety,
                ]
            )
        )
        self.j1.write_bytes(
            kv_bytes(
                [
                    *self._startup_common(
                        "dcentos.s19k-startup-j1-daemon-blocked/v1",
                        "2",
                        "dcentos.s19k-startup-c1-child-identity/v1",
                        digest(self.c1.read_bytes()),
                        self.c1.stat().st_size,
                    ),
                    *transcript_fields,
                    *safety,
                ]
            )
        )
        self.j2.write_bytes(
            kv_bytes(
                [
                    *self._startup_common(
                        "dcentos.s19k-startup-j2-child-bound/v1",
                        "3",
                        "dcentos.s19k-startup-j1-daemon-blocked/v1",
                        digest(self.j1.read_bytes()),
                        self.j1.stat().st_size,
                    ),
                    *transcript_fields,
                    *safety,
                ]
            )
        )
        self.release.write_bytes(
            kv_bytes(
                [
                    *self._startup_common(
                        "dcentos.s19k-startup-release/v1",
                        "3-release",
                        "dcentos.s19k-startup-j2-child-bound/v1",
                        digest(self.j2.read_bytes()),
                        self.j2.stat().st_size,
                    ),
                    ("parent_release", "true"),
                    ("publication", "no-clobber-hard-link-after-fsync"),
                ]
            )
        )

    def receipt_values(self) -> dict[str, str]:
        text = self.transcript.read_text(encoding="utf-8")
        values = {
            "schema": verifier.RECEIPT_SCHEMA,
            "deploy_mode": "handoff-no-work",
            "transcript_path": f"{REMOTE}/{self.transcript_name}",
            "transcript_mnt_id": "42",
            "transcript_inode": "4242",
            "transcript_mode": "0600",
            "transcript_uid": "0",
            "transcript_gid": "0",
            "transcript_sha256": digest(self.transcript.read_bytes()),
            "transcript_bytes": str(self.transcript.stat().st_size),
            "source_runtime_active_schema": verifier.SOURCE_RUNTIME_SCHEMA,
            "source_runtime_active_path": f"{REMOTE}/{self.source.name}",
            "source_runtime_active_sha256": digest(self.source.read_bytes()),
            "source_runtime_active_bytes": str(self.source.stat().st_size),
            "pending_runtime_schema": verifier.PENDING_RUNTIME_SCHEMA,
            "pending_runtime_path": f"{REMOTE}/{self.pending.name}",
            "pending_runtime_sha256": digest(self.pending.read_bytes()),
            "pending_runtime_bytes": str(self.pending.stat().st_size),
            "terminal_handoff_receipt_schema": verifier.TERMINAL_HANDOFF_SCHEMA,
            "terminal_handoff_receipt_path": f"{REMOTE}/{self.terminal.name}",
            "terminal_handoff_receipt_sha256": digest(self.terminal.read_bytes()),
            "terminal_handoff_receipt_bytes": str(self.terminal.stat().st_size),
            "safeoff_receipt_schema": verifier.SAFEOFF_SCHEMA,
            "safeoff_receipt_path": f"{REMOTE}/{self.safeoff.name}",
            "safeoff_receipt_sha256": digest(self.safeoff.read_bytes()),
            "safeoff_receipt_bytes": str(self.safeoff.stat().st_size),
            "startup_c1_schema": "dcentos.s19k-startup-c1-child-identity/v1",
            "startup_c1_path": f"{REMOTE}/{self.c1.name}",
            "startup_c1_sha256": digest(self.c1.read_bytes()),
            "startup_c1_bytes": str(self.c1.stat().st_size),
            "startup_j1_schema": "dcentos.s19k-startup-j1-daemon-blocked/v1",
            "startup_j1_path": f"{REMOTE}/{self.j1.name}",
            "startup_j1_sha256": digest(self.j1.read_bytes()),
            "startup_j1_bytes": str(self.j1.stat().st_size),
            "startup_j2_schema": "dcentos.s19k-startup-j2-child-bound/v1",
            "startup_j2_path": f"{REMOTE}/{self.j2.name}",
            "startup_j2_sha256": digest(self.j2.read_bytes()),
            "startup_j2_bytes": str(self.j2.stat().st_size),
            "startup_release_schema": "dcentos.s19k-startup-release/v1",
            "startup_release_path": f"{REMOTE}/{self.release.name}",
            "startup_release_sha256": digest(self.release.read_bytes()),
            "startup_release_bytes": str(self.release.stat().st_size),
            "binary_sha256": ARTIFACT_SHA,
            "binary_bytes": str(len(ARTIFACT_DATA)),
            "config_sha256": CONFIG_SHA,
            "config_bytes": str(len(CONFIG_DATA)),
            "runner_sha256": RUNNER_SHA,
            "runner_bytes": str(len(RUNNER_DATA)),
            "custody_observer_sha256": CUSTODY_SHA,
            "custody_observer_bytes": str(len(CUSTODY_DATA)),
            "stock_restart_helper_sha256": STOCK_HELPER_SHA,
            "stock_restart_helper_bytes": str(len(STOCK_HELPER_DATA)),
            "live_identity_schema": verifier.LIVE_IDENTITY_SCHEMA,
            "live_identity_profile": verifier.LIVE88_PROFILE,
            "live_identity_sha256": LIVE_SHA,
            "live_identity_model_sha256": MODEL_SHA,
            "wrapper_exit_status": "130",
            "no_work_active_count": str(text.count(verifier.NO_WORK_MARKER)),
            "discarded_job_count": str(text.count(verifier.DISCARDED_JOB_MARKER)),
            "full_frame_count": str(text.count(verifier.FULL_FRAME_MARKER)),
            "bounded_tx_count": str(text.count(verifier.BOUNDED_TX_MARKER)),
            "dispatch_admitted_count": str(
                text.count(verifier.DISPATCH_ADMITTED_MARKER)
            ),
            "semantic_verification": "host-plus-independent-instruments-required",
            "persistent_mutation": "false",
            "publication": "no-clobber-hard-link-after-fsync",
        }
        return values

    def write_receipt(self) -> None:
        values = self.receipt_values()
        self.receipt.write_bytes(
            kv_bytes([(key, values[key]) for key in verifier.RECEIPT_KEYS])
        )

    def write_manifest(self) -> None:
        files = {
            "preflight": self.preflight,
            "normalization_config": self.normalization_config,
            "normalization_receipt": self.normalization_receipt,
            "instrument_source": self.instrument_source,
            "instrument_csv": self.instrument_canonical,
            "uart_source": self.uart_source,
            "uart_csv": self.uart_canonical,
            "capture_contract": self.capture_contract,
            "capture_blocks": self.capture_blocks,
            "capture_verification": self.capture_verification,
        }
        values = {
            "schema": verifier.MANIFEST_SCHEMA,
            "claim": "joined-phase1-instrumentation+phase2-handoff-no-work",
            "plan_sha256": digest(self.plan.read_bytes()),
            "target_receipt_sha256": digest(self.receipt.read_bytes()),
            "transcript_sha256": digest(self.transcript.read_bytes()),
            "verifier_sha256": digest(Path(verifier.__file__).read_bytes()),
            "verifier_bytes": str(Path(verifier.__file__).stat().st_size),
            "preparer_sha256": digest(PREPARER_PATH.read_bytes()),
            "preparer_bytes": str(PREPARER_PATH.stat().st_size),
            "normalizer_sha256": digest(NORMALIZER_PATH.read_bytes()),
            "normalizer_bytes": str(NORMALIZER_PATH.stat().st_size),
            "capture_verifier_sha256": digest(CAPTURE_VERIFIER_PATH.read_bytes()),
            "capture_verifier_bytes": str(CAPTURE_VERIFIER_PATH.stat().st_size),
            "common_clock_id": "scope-logic-common-clock-001",
            "rail_signal": "rail-millivolts",
            "created_utc": "2026-08-22T12:00:00Z",
            "publication": "post-run-content-manifest",
        }
        for prefix, path in files.items():
            values[f"{prefix}_file"] = path.name
            values[f"{prefix}_sha256"] = digest(path.read_bytes())
            values[f"{prefix}_bytes"] = str(path.stat().st_size)
        self.manifest.write_bytes(
            kv_bytes([(key, values[key]) for key in verifier.MANIFEST_KEYS])
        )

    def write_bundle(self) -> None:
        result = verifier.verify(
            self.plan,
            self.trial,
            self.evidence,
            require_bundle_complete=False,
        )
        result_data = verifier._canonical_result_bytes(result)
        result_path = self.evidence / verifier.EMBEDDED_RESULT_FILENAME
        result_path.write_bytes(result_data)
        values = {
            "schema": verifier.BUNDLE_SCHEMA,
            "instrument_manifest_sha256": digest(self.manifest.read_bytes()),
            "instrument_manifest_bytes": str(self.manifest.stat().st_size),
            "host_verification_sha256": digest(result_data),
            "host_verification_bytes": str(len(result_data)),
            "verification_id": str(result["verification_id"]),
            "preparer_sha256": digest(PREPARER_PATH.read_bytes()),
            "preparer_bytes": str(PREPARER_PATH.stat().st_size),
            "file_count": str(len(verifier.EVIDENCE_FILENAMES) + 3),
            "publication": "host-staged-hard-link-bundle-and-directory-fsync",
        }
        (self.evidence / verifier.BUNDLE_RECEIPT_FILENAME).write_bytes(
            kv_bytes([(key, values[key]) for key in verifier.BUNDLE_KEYS])
        )

    def write_normalization_receipt(
        self, derived: dict[str, object] | None = None
    ) -> None:
        temporary_instrument = self.root / ".normalization-instrument.tmp"
        temporary_uart = self.root / ".normalization-uart.tmp"
        if derived is None:
            for path in (temporary_instrument, temporary_uart):
                if path.exists():
                    path.unlink()
            derived = normalizer._derive_files(
                self.normalization_config,
                self.instrument_source,
                self.uart_source,
                temporary_instrument,
                temporary_uart,
            )
            if (
                temporary_instrument.read_bytes()
                != self.instrument_canonical.read_bytes()
            ):
                raise AssertionError(
                    "instrument fixture is not its normalized derivation"
                )
            if temporary_uart.read_bytes() != self.uart_canonical.read_bytes():
                raise AssertionError("UART fixture is not its normalized derivation")
            temporary_instrument.unlink()
            temporary_uart.unlink()
        config_sha, config_bytes = normalizer._stable_digest(
            self.normalization_config, "fixture normalization config"
        )
        instrument_sha, instrument_bytes = normalizer._stable_digest(
            self.instrument_source, "fixture raw instrument export"
        )
        uart_sha, uart_bytes = normalizer._stable_digest(
            self.uart_source, "fixture raw UART export"
        )
        values = normalizer._receipt_values(
            config_sha256=config_sha,
            config_bytes=config_bytes,
            instrument_source_sha256=instrument_sha,
            instrument_source_bytes=instrument_bytes,
            uart_source_sha256=uart_sha,
            uart_source_bytes=uart_bytes,
            derived=derived,
        )
        self.normalization_receipt.write_bytes(
            normalizer._kv_bytes(normalizer.RECEIPT_KEYS, values)
        )

    def replace_instrument(self, old: str, new: str) -> None:
        text = self.instrument_canonical.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"instrument fixture token not found: {old}")
        self.instrument_canonical.write_text(
            text.replace(old, new, 1), encoding="utf-8", newline=""
        )
        raw = self.instrument_source.read_text(encoding="utf-8")
        self.instrument_source.write_text(
            raw.replace(old, new, 1), encoding="utf-8", newline=""
        )
        self.write_normalization_receipt()
        self.write_manifest()

    def replace_uart(self, old: str, new: str) -> None:
        text = self.uart_canonical.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"UART fixture token not found: {old}")
        self.uart_canonical.write_text(
            text.replace(old, new, 1), encoding="utf-8", newline=""
        )
        raw = self.uart_source.read_text(encoding="utf-8")
        self.uart_source.write_text(
            raw.replace(old, new, 1), encoding="utf-8", newline=""
        )
        self.write_normalization_receipt()
        self.write_manifest()


class NoWorkVerifyTests(unittest.TestCase):
    def test_instrument_rejects_sample_outside_reviewed_range(self) -> None:
        capture = instrument_csv().replace(b"14000,3050", b"20000,3050", 1)
        with self.assertRaisesRegex(verifier.VerificationError, "reviewed range"):
            verifier._parse_instrument(
                capture,
                80_000,
                rail_range_min=0,
                rail_range_max=15_000,
            )

    def test_preflight_accepts_method_specific_current_clamp_rating(self) -> None:
        data = preflight_data()
        for old, new in (
            (b"measurement_method=isolated-differential-voltage", b"measurement_method=noninvasive-current-clamp"),
            (b"expected_range_max=15000", b"expected_range_max=200000"),
            (b"expected_range_unit=millivolts", b"expected_range_unit=milliamps"),
            (b"instrument_voltage_rating_millivolts=30000", b"instrument_voltage_rating_millivolts=0"),
            (b"instrument_current_rating_milliamps=0", b"instrument_current_rating_milliamps=250000"),
            (b"instrument_isolation=isolated-differential", b"instrument_isolation=noninvasive"),
            (b"rail_capture_topology=two-isolated-slot-voltage-channels", b"rail_capture_topology=two-slot-dc-feed-current-clamps-one-polarity"),
            (b"rail_composite_rule=maximum-of-slot2-and-slot3-magnitude", b"rail_composite_rule=sum-of-slot2-and-slot3-magnitude"),
        ):
            data = data.replace(old, new, 1)
        result = verify_preflight_only(data, "rail-current-milliamps")
        self.assertEqual(result["preflight_current_rating_milliamps"], 250_000)

    def test_preflight_rejects_wall_or_aggregate_ac_current_topology(self) -> None:
        data = preflight_data()
        for old, new in (
            (b"measurement_method=isolated-differential-voltage", b"measurement_method=noninvasive-current-clamp"),
            (b"expected_range_max=15000", b"expected_range_max=200000"),
            (b"expected_range_unit=millivolts", b"expected_range_unit=milliamps"),
            (b"instrument_voltage_rating_millivolts=30000", b"instrument_voltage_rating_millivolts=0"),
            (b"instrument_current_rating_milliamps=0", b"instrument_current_rating_milliamps=250000"),
            (b"instrument_isolation=isolated-differential", b"instrument_isolation=noninvasive"),
            (b"rail_capture_topology=two-isolated-slot-voltage-channels", b"rail_capture_topology=wall-ac-input-current"),
            (b"rail_composite_rule=maximum-of-slot2-and-slot3-magnitude", b"rail_composite_rule=aggregate-wall-current"),
        ):
            data = data.replace(old, new, 1)
        with self.assertRaisesRegex(verifier.VerificationError, "rail_capture_topology"):
            verify_preflight_only(data, "rail-current-milliamps")

    def test_preflight_rejects_one_hz_gpio_edge_capture(self) -> None:
        data = preflight_data().replace(
            b"gpio_edge_sample_rate_hz=100000",
            b"gpio_edge_sample_rate_hz=1",
            1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "below 100 kHz"):
            verify_preflight_only(data)

    def test_preflight_rejects_underrated_loaded_or_slow_digital_channels(self) -> None:
        cases = (
            (b"gpio_input_rating_millivolts=25000", b"gpio_input_rating_millivolts=4999", "GPIO input"),
            (b"fan_tach_input_impedance_ohms=1000000", b"fan_tach_input_impedance_ohms=999999", "one megohm"),
            (b"fan_tach_sample_rate_hz=10000", b"fan_tach_sample_rate_hz=9999", "below 10 kHz"),
            (b"uart_sample_rate_hz=25000000", b"uart_sample_rate_hz=24999999", "eight-times"),
        )
        for old, new, message in cases:
            with self.subTest(field=old.decode("ascii").split("=", 1)[0]):
                with self.assertRaisesRegex(verifier.VerificationError, message):
                    verify_preflight_only(preflight_data().replace(old, new, 1))

    def test_preflight_rejects_duplicate_gpio_probe_channel_or_point(self) -> None:
        for old, new in (
            (b"gpio454_channel=logic-D1", b"gpio454_channel=logic-D0"),
            (
                b"gpio454_test_point=am3-s19k-gpio454-reviewed-pad",
                b"gpio454_test_point=am3-s19k-gpio437-reviewed-pad",
            ),
        ):
            with self.subTest(old=old):
                with self.assertRaisesRegex(verifier.VerificationError, "must be unique"):
                    verify_preflight_only(preflight_data().replace(old, new, 1))

    def test_preflight_rejects_duplicate_rail_tach_or_uart_channel(self) -> None:
        cases = (
            (b"rail_slot3_channel=scope-CH2", b"rail_slot3_channel=scope-CH1", "rail channels"),
            (b"fan1_tach_channel=logic-D5", b"fan1_tach_channel=logic-D4", "fan tach"),
            (b"ttys1_tx_channel=logic-D9", b"ttys1_tx_channel=logic-D8", "UART channels"),
        )
        for old, new, message in cases:
            with self.subTest(field=old):
                with self.assertRaisesRegex(verifier.VerificationError, message):
                    verify_preflight_only(preflight_data().replace(old, new, 1))

    def test_preflight_rejects_method_specific_underrating(self) -> None:
        data = preflight_data().replace(
            b"instrument_voltage_rating_millivolts=30000",
            b"instrument_voltage_rating_millivolts=14999",
            1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "voltage rating"):
            verify_preflight_only(data)

    def test_preflight_rejects_unreviewed_cat_rating(self) -> None:
        data = preflight_data().replace(
            b"instrument_cat_rating=CAT-III-600V",
            b"instrument_cat_rating=unknown",
            1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "CAT rating"):
            verify_preflight_only(data)

    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], EvidenceFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, EvidenceFixture(Path(temporary.name))

    def test_accepts_complete_target_and_independent_instrument_evidence(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = verifier.verify(fixture.plan, fixture.trial, fixture.evidence)
        self.assertEqual(result["required_paths"], list(verifier.REQUIRED_PATHS))
        self.assertEqual(result["uart_work_frame_count"], 0)
        self.assertEqual(
            result["publication"], "host-create-new-file-and-directory-fsync"
        )
        self.assertLess(result["reset_low_ms"], result["gpio437_cut_ms"])
        self.assertRegex(str(result["verification_id"]), r"^[0-9a-f]{64}$")

    @unittest.skipUnless(os.name == "posix", "CLI publication is a Linux/WSL gate")
    def test_cli_publishes_external_result_and_success_sentinel(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        output = fixture.root / "external-phase12-verification.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = verifier.main(
                [
                    "--plan",
                    str(fixture.plan),
                    "--trial-dir",
                    str(fixture.trial),
                    "--instrument-dir",
                    str(fixture.evidence),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("S19K_PHASE12_NO_WORK_OK", stdout.getvalue())
        self.assertEqual(
            json.loads(output.read_text(encoding="ascii"))["verification_id"],
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)[
                "verification_id"
            ],
        )

    def test_rejects_target_transcript_changed_after_wrapper_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.transcript.write_bytes(fixture.transcript.read_bytes() + b"tamper\n")
        with self.assertRaisesRegex(verifier.VerificationError, "wrapper receipt"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_work_frame_even_when_uart_manifest_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_uart(
            "55AA510900280000301112",
            "55AA213600000000000000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden 55AA2136"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_manual_canonical_edit_even_when_manifest_is_rehashed(
        self,
    ) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_canonical.write_text(
            fixture.uart_canonical.read_text(encoding="utf-8").replace(
                "55AA510900280000301112",
                "55AA510900280000301113",
                1,
            ),
            encoding="utf-8",
            newline="",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(
            verifier.VerificationError, "capture normalization provenance"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_raw_export_edit_even_when_manifest_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.instrument_source.write_text(
            fixture.instrument_source.read_text(encoding="utf-8").replace(
                "14000,3050",
                "14001,3050",
                1,
            ),
            encoding="utf-8",
            newline="",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(
            verifier.VerificationError, "capture normalization provenance"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_work_frame_embedded_in_batched_uart_record(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_uart(
            "55AA510900280000301112",
            "AA0055AA213600000000000000BB",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden 55AA2136"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_work_signature_split_across_adjacent_tx_rows(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_uart(
            "3200,/dev/ttyS1,tx,55AA510900280000301112",
            "3200,/dev/ttyS1,tx,55AA",
        )
        fixture.replace_uart(
            "3300,/dev/ttyS1,rx,AA55010203040506070809",
            "3300,/dev/ttyS1,tx,21360000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden 55AA2136"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_reset_low_only_after_gpio437_cut(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_instrument(
            "4000,sample,13900,3050,3040,3030,3020,55000,61000,54000,60000,0,0,0,0",
            "4000,sample,13900,3050,3040,3030,3020,55000,61000,54000,60000,0,0,1,1",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "all low before"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_reset_to_cut_timing_margin_too_small(self) -> None:
        capture = instrument_csv().replace(b"5000,sample,12000", b"4001,sample,12000", 1)
        with self.assertRaisesRegex(verifier.VerificationError, "two-millisecond"):
            verifier._parse_instrument(
                capture,
                80_000,
                rail_range_min=0,
                rail_range_max=15_000,
            )

    def test_rejects_missing_independent_rail_decay(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.instrument_canonical.read_text(encoding="utf-8")
        text = re.sub(
            r"(?m)^(8|9|10|11|12|13|14)000,sample,(?:600|300),",
            r"\g<1>000,sample,9000,",
            text,
        )
        fixture.instrument_canonical.write_text(text, encoding="utf-8", newline="")
        fixture.instrument_source.write_text(text, encoding="utf-8", newline="")
        fixture.write_normalization_receipt()
        fixture.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "never decayed"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_cooling_loss_before_decay_confirmation(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_instrument(
            "10000,sample,300,3050,3040,3030,3020",
            "10000,sample,300,0,0,0,0",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "cooling evidence"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_common_clock_sampling_gap(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        lines = fixture.instrument_canonical.read_text(encoding="utf-8").splitlines()
        lines = [line for line in lines if not line.startswith("10000,")]
        fixture.instrument_canonical.write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline=""
        )
        fixture.instrument_source.write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline=""
        )
        fixture.write_normalization_receipt()
        fixture.write_manifest()
        with self.assertRaisesRegex(
            verifier.VerificationError, "gap larger than one second"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_rail_rebound_after_decay_confirmation(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_instrument(
            "14000,sample,300,3050,3040,3030,3020",
            "14000,sample,9000,3050,3040,3030,3020",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "rebounded"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_sampling_gap_after_decay_confirmation(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_instrument("14000,sample,", "16000,sample,")
        with self.assertRaisesRegex(verifier.VerificationError, "through capture end"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_cooling_loss_after_decay_confirmation(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_instrument(
            "14000,sample,300,3050,3040,3030,3020",
            "14000,sample,300,0,0,0,0",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "before capture end"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_stale_instrumentation_preflight(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.preflight.write_text(
            fixture.preflight.read_text(encoding="ascii").replace(
                "authorized_utc=2026-08-22T11:30:00Z",
                "authorized_utc=2026-08-20T11:30:00Z",
            ).replace(
                "disconnect_tested_utc=2026-08-22T11:20:00Z",
                "disconnect_tested_utc=2026-08-20T11:20:00Z",
            ),
            encoding="ascii",
            newline="",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "older than 24 hours"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_preflight_for_another_common_clock(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.preflight.write_text(
            fixture.preflight.read_text(encoding="ascii").replace(
                "common_clock_id=scope-logic-common-clock-001",
                "common_clock_id=another-clock",
            ),
            encoding="ascii",
            newline="",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "common_clock_id"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_canonical_capture_over_size_limit(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        original_limit = verifier.MAX_CANONICAL_BYTES
        verifier.MAX_CANONICAL_BYTES = 64
        self.addCleanup(setattr, verifier, "MAX_CANONICAL_BYTES", original_limit)
        with self.assertRaisesRegex(verifier.VerificationError, "64 MiB canonical"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_startup_chain_substitution_even_when_receipt_is_rehashed(
        self,
    ) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.j1.read_text(encoding="utf-8").replace(
            f"predecessor_sha256={digest(fixture.c1.read_bytes())}",
            f"predecessor_sha256={'0' * 64}",
        )
        fixture.j1.write_text(text, encoding="utf-8", newline="")
        fixture.write_receipt()
        fixture.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "predecessor_sha256"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_dry_run_plan_for_physical_evidence(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.plan.write_text(
            fixture.plan.read_text(encoding="utf-8").replace(
                "dry_run=false", "dry_run=true"
            ),
            encoding="utf-8",
            newline="",
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(verifier.VerificationError, "dry_run"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_manifest_bound_to_another_target_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.manifest.read_text(encoding="utf-8").replace(
            f"target_receipt_sha256={digest(fixture.receipt.read_bytes())}",
            f"target_receipt_sha256={'0' * 64}",
        )
        fixture.manifest.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(
            verifier.VerificationError, "target_receipt_sha256"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_manifest_bound_to_another_verifier(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        verifier_sha = digest(Path(verifier.__file__).read_bytes())
        text = fixture.manifest.read_text(encoding="utf-8").replace(
            f"verifier_sha256={verifier_sha}",
            f"verifier_sha256={'0' * 64}",
        )
        fixture.manifest.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "verifier_sha256"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_manifest_bound_to_another_preparer(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        preparer_sha = digest(PREPARER_PATH.read_bytes())
        text = fixture.manifest.read_text(encoding="utf-8").replace(
            f"preparer_sha256={preparer_sha}",
            f"preparer_sha256={'0' * 64}",
        )
        fixture.manifest.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "preparer_sha256"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_manifest_bound_to_another_normalizer(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        normalizer_sha = digest(NORMALIZER_PATH.read_bytes())
        text = fixture.manifest.read_text(encoding="utf-8").replace(
            f"normalizer_sha256={normalizer_sha}",
            f"normalizer_sha256={'0' * 64}",
        )
        fixture.manifest.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "normalizer_sha256"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_missing_bundle_completion_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        (fixture.evidence / verifier.BUNDLE_RECEIPT_FILENAME).unlink()
        with self.assertRaisesRegex(verifier.VerificationError, "completion receipt"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_tampered_embedded_semantic_result(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result_path = fixture.evidence / verifier.EMBEDDED_RESULT_FILENAME
        result_path.write_bytes(result_path.read_bytes() + b" ")
        with self.assertRaisesRegex(verifier.VerificationError, "differs from fresh"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_extra_bundle_member(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        (fixture.evidence / "unbound-note.txt").write_text(
            "not evidence\n", encoding="ascii"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "contains extras"):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    def test_rejects_noncanonical_bundle_member_name(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        renamed = fixture.evidence / "operator-selected-scope-name.raw"
        fixture.instrument_source.rename(renamed)
        text = fixture.manifest.read_text(encoding="utf-8").replace(
            "instrument_source_file=instrument_source.raw",
            f"instrument_source_file={renamed.name}",
        )
        fixture.manifest.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(
            verifier.VerificationError, "instrument_source_file"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)

    @unittest.skipUnless(os.name == "posix", "hard-link count is a Linux/WSL gate")
    def test_rejects_bundle_member_with_external_hard_link(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        os.link(fixture.instrument_source, fixture.root / "alias.raw")
        with self.assertRaisesRegex(
            verifier.VerificationError, "exactly one hard link"
        ):
            verifier.verify(fixture.plan, fixture.trial, fixture.evidence)


@unittest.skipUnless(
    os.name == "posix", "directory fsync publication is a Linux/WSL gate"
)
class ResultPublicationTests(unittest.TestCase):
    def test_publishes_once_with_file_and_directory_fsync(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase12_verification.json"
            result = {
                "schema": verifier.VERIFICATION_SCHEMA,
                "verification_id": "a" * 64,
            }
            verifier._publish_result(output, result)
            self.assertEqual(json.loads(output.read_text(encoding="ascii")), result)
            with self.assertRaisesRegex(
                verifier.VerificationError, "refusing to clobber"
            ):
                verifier._publish_result(output, result)


class RunnerNoWorkReceiptContractTests(unittest.TestCase):
    def test_runner_binds_exact_no_work_transcript_after_safeoff(self) -> None:
        source = (SCRIPT_DIR / "dcentrald_s19k_tmp_remote_run.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'NO_WORK_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_handoff_no_work_transcript"',
            source,
        )
        # f2d3b9bc6 widened the transcript-hold gate to a multi-line condition
        # that also covers install-custody-safeoff; assert the receipt-bearing
        # modes still gate the exec 6< inode hold, then that the hold precedes
        # the daemon launch.
        self.assertIn('[ "$DEPLOY_MODE" = handoff-no-work ]', source)
        self.assertIn('[ "$DEPLOY_MODE" = bounded-work-proof ]', source)
        hold = source.index('exec 6< "$STARTUP_DAEMON_TRANSCRIPT"')
        launch = source.index(
            '"$@" 6>&- 9>&- </dev/null >>"$STARTUP_DAEMON_TRANSCRIPT"'
        )
        self.assertLess(hold, launch)
        block = source.split(
            'NO_WORK_TMP="$TRIAL_DIR/.runtime_handoff_no_work_transcript.tmp.$$.${SELF_START}"',
            1,
        )[1].split('    } > "$NO_WORK_TMP"', 1)[0]
        emitted: list[str] = []
        for format_string in re.findall(r"printf '([^']*)'", block):
            for line in format_string.split(r"\n"):
                if "=" in line:
                    emitted.append(line.split("=", 1)[0])
        self.assertEqual(tuple(emitted), verifier.RECEIPT_KEYS)
        self.assertIn(
            'wc -l < "$NO_WORK_TRANSCRIPT_RECEIPT" | tr -d \' \\t\\r\\n\')" -eq 65',
            source,
        )
        # The no-work receipt is now published by the consolidated
        # publish_mode_specific_receipts_after_safeoff() helper, which every
        # checked-SafeOff exit path invokes immediately after clearing the
        # runtime obligation; the helper in turn binds the no-work transcript.
        for branch_tail in (
            'clear_runtime_obligation_after_safeoff || exit 1\n        publish_mode_specific_receipts_after_safeoff "$EXIT_CODE"',
            'clear_runtime_obligation_after_safeoff || exit 1\n    publish_mode_specific_receipts_after_safeoff "$CHILD_STATUS"',
        ):
            self.assertIn(branch_tail, source)
        unified = source.index("publish_mode_specific_receipts_after_safeoff() {")
        self.assertIn('publish_handoff_no_work_transcript_receipt "$', source[unified:])


if __name__ == "__main__":
    unittest.main()
