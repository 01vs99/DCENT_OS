"""Tests for the emu-twin end-to-end scenario harness (I2-owned).

The scenario is the seed of the campaign Phase-A exit test ("twin returns a
genuinely valid share"): job -> chain -> real-sha256d nonce -> submit ->
stub revalidation -> independent harness recompute -> PASS/FAIL + JSON
evidence. I1's ``chain_server``/``nonce_engine`` modules are OPTIONAL here —
when they are absent the built-in backend serves and the tests still pass;
the I1-integration test skips with an explicit reason.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import harness.scenario_run as scenario  # noqa: E402
import stratum_stub  # noqa: E402

SCENARIO_DIFFICULTY = 0.00005  # ~1 in 90k nonces; fast even on one core


@pytest.fixture()
def evidence_dir(tmp_path):
    return tmp_path / "evidence"


def test_builtin_header_search_finds_accept_all_target_immediately():
    import struct

    header = scenario.build_work_header(
        stratum_stub.make_job(0), b"\x00\x00\x00\x01", b"\x00\x00\x00\x00"
    )
    assert len(header) == 80
    target = bytes([0xFF] * 32)  # accept-all sentinel
    result = scenario.find_nonce_for_header(header, target, max_attempts=16)
    assert result is not None
    nonce, digest = result
    assert digest <= target
    # the winning header must be the dispatched header with the found nonce
    assert header[76:80] == struct.pack("<I", nonce)


def test_run_scenario_passes_end_to_end(evidence_dir):
    evidence = scenario.run_scenario(
        name="pytest-e2e",
        difficulty=SCENARIO_DIFFICULTY,
        evidence_dir=evidence_dir,
        max_chain_attempts=2_000_000,
        chain_timeout_secs=90.0,
        extranonce2_tries=6,
        quiet=True,
    )
    assert evidence["verdict"] == "PASS", evidence.get("reason")
    assert evidence["schema"] == scenario.SCHEMA
    assert evidence["model_tier"] == scenario.MODEL_TIER  # honesty label


def test_evidence_file_written_with_hashes(evidence_dir):
    evidence = scenario.run_scenario(
        name="pytest-evidence",
        difficulty=SCENARIO_DIFFICULTY,
        evidence_dir=evidence_dir,
        quiet=True,
        max_chain_attempts=2_000_000,
    )
    path = Path(str(evidence["evidence_path"]))
    assert path.exists()
    assert path.parent == evidence_dir.resolve() or path.parent == evidence_dir
    loaded = json.loads(path.read_text(encoding="utf-8"))

    # structural truth: every step of the timeline is timestamped
    steps = [s["step"] for s in loaded["steps"]]
    for expected in (
        "stratum-stub-start",
        "chain-backend",
        "subscribed",
        "authorized",
        "job-received",
        "chain-dispatch",
        "share-submitted",
        "share-verdict",
        "independent-recompute",
    ):
        assert expected in steps, f"missing timeline step {expected!r}"

    # hash truth: the stub's share record and the independent recompute agree
    share = loaded["share"]
    recomputed = stratum_stub.sha256d(bytes.fromhex(share["header_hex"]))
    assert recomputed.hex() == share["share_hash"]
    assert recomputed <= bytes.fromhex(share["target"])
    assert loaded["independent_check"]["matches_stub"] is True
    assert loaded["independent_check"]["recomputed_hash"] == share["share_hash"]

    # the chain actually saw the job that produced the share
    assert loaded["chain_jobs"], "chain backend received no job dispatch"
    assert loaded["chain_response"]["found"] is True
    dispatched = bytes.fromhex(loaded["chain_jobs"][0]["header_hex"])
    assert len(dispatched) == 80
    assert loaded["stratum"]["accepted"] == 1
    assert loaded["stratum"]["difficulty"] == SCENARIO_DIFFICULTY


def test_cli_exit_code_zero_on_pass(evidence_dir, capsys):
    code = scenario.main(
        [
            "--name", "pytest-cli",
            "--difficulty", str(SCENARIO_DIFFICULTY),
            "--evidence-dir", str(evidence_dir),
            "--max-chain-attempts", "2000000",
            "--quiet",
        ]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["verdict"] == "PASS"
    assert Path(summary["evidence"]).exists()


def test_optional_module_loader_never_raises():
    assert scenario.load_optional_module("definitely_not_a_module_xyz") is None


def test_chain_backend_resolution_records_i1_presence():
    backend, info = scenario.resolve_chain_backend("auto")
    assert "builtin-chain-stub" in backend
    assert "chain_server_module_present" in info
    # explicit builtin preference never imports I1
    backend_builtin, _ = scenario.resolve_chain_backend("builtin")
    assert backend_builtin == "builtin-chain-stub"


def test_i1_chain_server_integration_or_skip():
    """Runs only when I1's chain_server module has landed; skips cleanly."""
    module = scenario.load_optional_module("chain_server")
    if module is None:
        pytest.skip("I1 chain_server not present yet — builtin backend covers this wave")
    backend, info = scenario.resolve_chain_backend("auto")
    assert info["chain_server_module_present"] is True
    assert "chain_server" in backend


def test_i1_nonce_engine_probe_degrades_to_builtin():
    """EngineProbe must resolve to builtin-hashlib when nonce_engine is absent,
    and must never raise when the module exists but signatures differ."""
    probe = scenario.EngineProbe()
    if probe.module is None:
        assert probe.engine_name == "builtin-hashlib"
    header = scenario.build_work_header(
        stratum_stub.make_job(9), b"\x00\x00\x00\x02", b"\x00\x00\x00\x07"
    )
    target = bytes([0xFF] * 32)
    result = probe.search(header, target, 0, 8, 5.0)
    assert result is not None  # builtin path always serves the accept-all case
