#!/usr/bin/env python3
"""Adversarial tests for the S19k bounded-work evidence verifier."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_bounded_transcript_verify as verifier  # noqa: E402


ARTIFACT_DATA = b"fixture-armv7-dcentrald\n"
CONFIG_DATA = b"[platform]\ntarget = \"am3-aml-s19k\"\n"
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
REMOTE = "/tmp/dcentrald_bench_t1_fixture"
PATHS = ("/dev/ttyS1", "/dev/ttyS2")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kv_bytes(fields: list[tuple[str, str]]) -> bytes:
    return ("".join(f"{key}={value}\n" for key, value in fields)).encode("utf-8")


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc5(data: bytes) -> int:
    crc = 0x1F
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            top = (crc >> 4) & 1
            crc = (crc << 1) & 0x1F
            if bit ^ top:
                crc ^= 0x05
    return crc


def tx_wire(job_id: int = 16) -> str:
    body = bytearray(84)
    body[0:4] = bytes((0x21, 0x36, job_id, 0x01))
    for index in range(4, len(body)):
        body[index] = (index * 7) & 0xFF
    checksum = crc16(bytes(body))
    wire = bytes((0x55, 0xAA)) + bytes(body) + checksum.to_bytes(2, "big")
    assert len(wire) == 88
    return wire.hex().upper()


def rx_wire(seed: int) -> str:
    first = bytes(((seed + index * 13) & 0xFF for index in range(8)))
    trailer = next(value for value in range(256) if crc5(first + bytes((value,))) == 0)
    body = first + bytes((trailer,))
    assert crc5(body) == 0
    wire = bytes((0xAA, 0x55)) + body
    assert len(wire) == 11
    return wire.hex().upper()


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
        ("live_identity_profile", "live88_two_bhb56903_slots_2_3"),
        ("live_identity_sha256", LIVE_SHA),
        ("live_identity_model_sha256", MODEL_SHA),
    ]


def transcript_text() -> str:
    tx = tx_wire()
    rx1 = rx_wire(0x11)
    rx2 = rx_wire(0x22)
    required = '["/dev/ttyS1", "/dev/ttyS2"]'
    accepted = '{"/dev/ttyS1", "/dev/ttyS2"}'
    committed = (
        '[SerialPathTxReceipt { path: "/dev/ttyS1", committed: true, error: None }, '
        'SerialPathTxReceipt { path: "/dev/ttyS2", committed: true, error: None }]'
    )
    work = "WorkGeneration { session: 1, job: 2 }"
    lines = [
        f'INFO dcentrald::serial_mining: {verifier.STARTED} schema="{verifier.PROOF_SCHEMA}" required_paths={required} timeout_s=600 evidence="all-crc-admitted-rx+all-required-path-tx+exact-pool-result-origin"',
        f'INFO dcentrald::serial_mining: {verifier.TX} schema="{verifier.PROOF_SCHEMA}" event="tx-all-required-committed" ownership_epoch=7 commit_sequence=0 wrap_idx=0 wire_bytes=88 wire_hex={tx} asic_job_id=16 work_generation={work} pool_job_id=job-a paths={committed}',
        f'INFO dcentrald::serial_mining: {verifier.RX} schema="{verifier.PROOF_SCHEMA}" event="rx-crc-admitted" path="/dev/ttyS1" wire_bytes=11 wire_hex={rx1} crc_status="full-frame-zero-remainder"',
        f'INFO dcentrald::serial_mining: {verifier.ATTRIBUTION} schema="{verifier.PROOF_SCHEMA}" event="rx-share-attributed" path=Some("/dev/ttyS1") wire_hex={rx1} crc_status="full-frame-zero-remainder" raw_job_byte=0x10 resolved_asic_job_id=0x10 dispatch_generation=2 work_generation={work} pool_job_id=job-a nonce=0x11111111 version_bits=0x0000 rolled_version=0x20000000 attribution=Raw physical_chip_core=None meets_pool_target=true submit_allowed=true',
        f'INFO dcentrald::serial_mining: {verifier.POOL_RESULT} schema="{verifier.PROOF_SCHEMA}" event="pool-result" result="accepted" path="/dev/ttyS1" attribution=Raw physical_chip_core=None work_generation={work} pool_job_id=job-a worker_name=worker.1 extranonce2=00000001 ntime=68a40000 nonce=11111111 version_bits=None version=0x20000000',
        f'INFO dcentrald::serial_mining: {verifier.RX} schema="{verifier.PROOF_SCHEMA}" event="rx-crc-admitted" path="/dev/ttyS2" wire_bytes=11 wire_hex={rx2} crc_status="full-frame-zero-remainder"',
        f'INFO dcentrald::serial_mining: {verifier.ATTRIBUTION} schema="{verifier.PROOF_SCHEMA}" event="rx-share-attributed" path=Some("/dev/ttyS2") wire_hex={rx2} crc_status="full-frame-zero-remainder" raw_job_byte=0x10 resolved_asic_job_id=0x10 dispatch_generation=2 work_generation={work} pool_job_id=job-a nonce=0x22222222 version_bits=0x0000 rolled_version=0x20000000 attribution=Raw physical_chip_core=None meets_pool_target=true submit_allowed=true',
        f'INFO dcentrald::serial_mining: {verifier.POOL_RESULT} schema="{verifier.PROOF_SCHEMA}" event="pool-result" result="accepted" path="/dev/ttyS2" attribution=Raw physical_chip_core=None work_generation={work} pool_job_id=job-a worker_name=worker.1 extranonce2=00000002 ntime=68a40000 nonce=22222222 version_bits=None version=0x20000000',
        f'INFO dcentrald::serial_mining: {verifier.COMPLETE} schema="{verifier.PROOF_SCHEMA}" required_paths={required} accepted_paths={accepted}',
        "INFO dcentrald::serial_mining: Track-1 terminal GPIO437 SafeOff completed after reset attempts",
    ]
    return "\n".join(lines) + "\n"


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.trial = root / "copied-trial"
        self.trial.mkdir()
        self.plan = root / "live.plan"
        self.transcript_name = ".startup_daemon_transcript.100.200"
        self.transcript = self.trial / self.transcript_name
        self.source = self.trial / "runtime_active_pre_safeoff"
        self.pending = self.trial / "runtime_active"
        self.terminal = self.trial / "runtime_terminal_safeoff"
        self.safeoff = self.trial / "runtime_safeoff_terminal_receipt"
        self.receipt = self.trial / "runtime_bounded_work_transcript"
        for filename, data in (
            ("dcentrald", ARTIFACT_DATA),
            ("dcentrald_s19k.toml", CONFIG_DATA),
            ("run_trial", RUNNER_DATA),
            ("supervisor_custody_observer", CUSTODY_DATA),
            ("stock_restart_helper", STOCK_HELPER_DATA),
        ):
            (self.trial / filename).write_bytes(data)
        self._write_plan()
        self.transcript.write_text(transcript_text(), encoding="utf-8", newline="")
        self._write_bound_records()
        self.write_receipt()

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
            ("bounded_work_proof_flag", "--s19k-track1-bounded-work-proof"),
            ("work_proof_timeout_s", "600"),
            ("work_evidence", verifier.EXPECTED_WORK_EVIDENCE),
            ("work_proof_success", verifier.EXPECTED_SUCCESS),
            ("work_authority", "bounded-proof"),
            (
                "required_ports",
                "population-selected:/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
            ),
            ("mode", "bounded-work-proof"),
            ("native_bm1366", "refused"),
            ("clear_for_flash", "false"),
            ("dry_run", "false"),
            ("ssh_host_key_admission", "exact-operator-pin"),
            ("ssh_host_key_sha256", "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg"),
            ("ssh_global_known_hosts", "disabled-on-contact"),
        ]
        self.plan.write_bytes(kv_bytes(fields))

    def _write_bound_records(self) -> None:
        source_fields = [
            ("schema", verifier.SOURCE_RUNTIME_SCHEMA),
            ("phase", "child-live-or-recovery-required"),
            *artifact_fields(),
            *identity_fields(),
            ("deploy_mode", "bounded-work-proof"),
            ("persistent_mutation", "false"),
        ]
        self.source.write_bytes(kv_bytes(source_fields))

        safeoff_line = (
            "DCENT_S19K_TRACK1_SAFEOFF_RECEIPT "
            f"schema={verifier.SAFEOFF_SCHEMA} live_identity_sha256={LIVE_SHA} "
            "live_identity_profile=live88_two_bhb56903_slots_2_3 "
            f"live_identity_model_sha256={MODEL_SHA} live_identity_board_count=2 "
            "live_identity_physical_addresses=2,3 live_identity_board_names=BHB56903,BHB56903 "
            "live_identity_eeprom=0x50:absent,0x51:0511,0x52:0511 "
            "resets=454:0,455:0,456:0 psu=437:1\n"
        )
        self.safeoff.write_text(safeoff_line, encoding="utf-8", newline="")

        terminal_fields = [
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
        self.terminal.write_bytes(kv_bytes(terminal_fields))

        pending_fields = [
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
            ("terminal_handoff_receipt_schema", verifier.TERMINAL_HANDOFF_SCHEMA),
            ("terminal_handoff_receipt_sha256", digest(self.terminal.read_bytes())),
            ("terminal_handoff_receipt_bytes", str(self.terminal.stat().st_size)),
            ("resets", "454:0,455:0,456:0"),
            ("psu", "437:1"),
            ("dcentrald", "absent"),
            ("stock_supervisor", "absent"),
            ("stock_bosminer", "absent"),
            ("watchdog_fd", "absent"),
            ("persistent_mutation", "false"),
            ("next_authority", "exact-stock-restart-helper-only"),
        ]
        self.pending.write_bytes(kv_bytes(pending_fields))

    def receipt_values(self) -> dict[str, str]:
        text = self.transcript.read_text(encoding="utf-8")
        values = {
            "schema": verifier.RECEIPT_SCHEMA,
            "deploy_mode": "bounded-work-proof",
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
            "live_identity_profile": "live88_two_bhb56903_slots_2_3",
            "live_identity_sha256": LIVE_SHA,
            "live_identity_model_sha256": MODEL_SHA,
            "wrapper_exit_status": "0",
            "started_count": str(text.count(verifier.STARTED)),
            "tx_count": str(text.count(verifier.TX)),
            "rx_count": str(text.count(verifier.RX)),
            "attribution_count": str(text.count(verifier.ATTRIBUTION)),
            "pool_result_count": str(text.count(verifier.POOL_RESULT)),
            "complete_count": str(text.count(verifier.COMPLETE)),
            "incomplete_count": str(text.count(verifier.INCOMPLETE)),
            "semantic_verification": "host-required",
            "persistent_mutation": "false",
            "publication": "no-clobber-hard-link-after-fsync",
        }
        return values

    def write_receipt(self) -> None:
        values = self.receipt_values()
        self.receipt.write_bytes(kv_bytes([(key, values[key]) for key in verifier.RECEIPT_KEYS]))

    def replace_transcript(self, old: str, new: str) -> None:
        text = self.transcript.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"fixture token not found: {old}")
        self.transcript.write_text(text.replace(old, new, 1), encoding="utf-8", newline="")
        self.write_receipt()


class BoundedTranscriptVerifyTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], EvidenceFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, EvidenceFixture(Path(temporary.name))

    def test_accepts_complete_content_bound_two_uart_proof(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = verifier.verify(fixture.plan, fixture.trial)
        self.assertEqual(result["required_paths"], list(PATHS))
        self.assertEqual(result["accepted_paths"], list(PATHS))
        self.assertEqual(result["tx_count"], 1)
        self.assertEqual(result["rx_count"], 2)
        self.assertRegex(str(result["verification_id"]), r"^[0-9a-f]{64}$")

    def test_rejects_transcript_changed_after_wrapper_receipt(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.transcript.write_bytes(fixture.transcript.read_bytes() + b"tamper\n")
        with self.assertRaisesRegex(verifier.VerificationError, "wrapper receipt"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_invalid_closed11d_crc_even_when_receipt_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        wire = tx_wire()
        damaged = wire[:-2] + ("00" if wire[-2:] != "00" else "01")
        fixture.replace_transcript(f"wire_hex={wire}", f"wire_hex={damaged}")
        with self.assertRaisesRegex(verifier.VerificationError, "CRC16"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_invalid_rx_crc_even_when_receipt_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        wire = rx_wire(0x11)
        damaged = wire[:-2] + ("00" if wire[-2:] != "00" else "01")
        fixture.replace_transcript(f"wire_hex={wire}", f"wire_hex={damaged}")
        with self.assertRaisesRegex(verifier.VerificationError, "BM1366"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_pool_result_without_exact_attribution_origin(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_transcript("nonce=22222222", "nonce=33333333")
        with self.assertRaisesRegex(verifier.VerificationError, "exact RX attribution"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_missing_accepted_share_on_one_uart(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        needle = 'result="accepted" path="/dev/ttyS2"'
        fixture.replace_transcript(needle, 'result="rejected" path="/dev/ttyS2"')
        with self.assertRaisesRegex(verifier.VerificationError, "accepted share"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_incomplete_marker_even_with_complete_marker(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        with fixture.transcript.open("a", encoding="utf-8", newline="") as stream:
            stream.write(
                f'WARN dcentrald::serial_mining: {verifier.INCOMPLETE} '
                f'schema="{verifier.PROOF_SCHEMA}" required_paths=["/dev/ttyS1", "/dev/ttyS2"]\n'
            )
        fixture.write_receipt()
        with self.assertRaisesRegex(verifier.VerificationError, "zero INCOMPLETE"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_dry_run_plan_for_live_evidence(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.plan.read_text(encoding="utf-8").replace("dry_run=false", "dry_run=true")
        fixture.plan.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "dry_run"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_operator_artifact_pin_drift(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.plan.read_text(encoding="utf-8").replace(
            f"expected_artifact_sha256={ARTIFACT_SHA}",
            f"expected_artifact_sha256={'0' * 64}",
        )
        fixture.plan.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected_artifact_sha256",
        ):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_safeoff_companion_drift(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        text = fixture.safeoff.read_text(encoding="utf-8").replace("psu=437:1", "psu=437:0")
        fixture.safeoff.write_text(text, encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "wrapper receipt"):
            verifier.verify(fixture.plan, fixture.trial)

    def test_rejects_reordered_transcript_receipt_keys(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        lines = fixture.receipt.read_text(encoding="utf-8").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        fixture.receipt.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
        with self.assertRaisesRegex(verifier.VerificationError, "ordered keys"):
            verifier.verify(fixture.plan, fixture.trial)


class RunnerTranscriptReceiptContractTests(unittest.TestCase):
    def test_runner_holds_inode_and_publishes_only_after_checked_safeoff(self) -> None:
        source = (SCRIPT_DIR / "dcentrald_s19k_tmp_remote_run.sh").read_text(encoding="utf-8")
        self.assertIn('BOUNDED_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_bounded_work_transcript"', source)
        hold = source.index('exec 6< "$STARTUP_DAEMON_TRANSCRIPT"')
        launch = source.index('"$@" 6>&- 9>&- </dev/null >>"$STARTUP_DAEMON_TRANSCRIPT"')
        self.assertLess(hold, launch)
        self.assertIn("schema=dcentos.s19k-bounded-work-transcript/v1", source)
        self.assertIn("semantic_verification=host-required", source)
        block = source.split(
            'BOUNDED_TMP="$TRIAL_DIR/.runtime_bounded_work_transcript.tmp.$$.${SELF_START}"',
            1,
        )[1].split('    } > "$BOUNDED_TMP"', 1)[0]
        emitted: list[str] = []
        for format_string in re.findall(r"printf '([^']*)'", block):
            for line in format_string.split(r"\n"):
                if "=" in line:
                    emitted.append(line.split("=", 1)[0])
        self.assertEqual(tuple(emitted), verifier.RECEIPT_KEYS)
        self.assertIn(
            'wc -l < "$BOUNDED_TRANSCRIPT_RECEIPT" | tr -d \' \\t\\r\\n\')" -eq 51',
            source,
        )
        # f2d3b9bc6 consolidated the per-mode receipt publications into
        # publish_mode_specific_receipts_after_safeoff(), the SOLE caller of
        # publish_bounded_work_transcript_receipt. It emits install-custody ->
        # no-work -> bounded-work -> endurance in order, so the bounded receipt
        # still follows the no-work receipt. The live-safety contract is
        # unchanged and now enforced at EVERY invocation of the unified helper:
        # each is immediately preceded by a checked-SafeOff proof.
        calls = [
            match.start()
            for match in re.finditer(r'publish_bounded_work_transcript_receipt "\$', source)
        ]
        self.assertEqual(len(calls), 1)
        unified = source.index("publish_mode_specific_receipts_after_safeoff() {")
        self.assertLess(
            source.index('publish_handoff_no_work_transcript_receipt "$', unified),
            source.index('publish_bounded_work_transcript_receipt "$', unified),
        )
        invocations = [
            match.start()
            for match in re.finditer(
                r'\n *publish_mode_specific_receipts_after_safeoff "\$', source
            )
        ]
        self.assertTrue(invocations)
        for call in invocations:
            preceding_line = source[:call].rsplit("\n", 1)[-1].strip()
            self.assertIn(
                preceding_line,
                {
                    "clear_runtime_obligation_after_safeoff || exit 1",
                    "transition_startup_stock_loss_to_pending || exit 1",
                },
            )


if __name__ == "__main__":
    unittest.main()
