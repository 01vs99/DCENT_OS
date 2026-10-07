"""Tests for the emu-twin Stratum V1 stub pool (I2-owned).

Covers: share-target math (fail-closed semantics mirrored from the production
``dcentrald-stratum`` difficulty.rs), header construction helpers, the
handshake wire shapes the production V1 client sends, and — the core
deliverable — the stub issuing a job, the TEST computing a share itself with
real sha256d, and the stub re-validating that share by recomputation.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import stratum_stub
from stratum_stub import (
    PDIFF1_TARGET_INT,
    StratumStub,
    build_header,
    difficulty_to_target_int,
    find_share,
    make_job,
    merkle_root,
    meets_target,
    reverse_words_per_4,
    sha256d,
    target_int_to_bytes,
)

# A difficulty low enough that a real-sha256d search succeeds in well under a
# second on one core (target ~2^238 -> ~1 in 90k nonces).
TEST_DIFFICULTY = 0.00005


# ---------------------------------------------------------------------------
# Target math (mirror of difficulty.rs contracts)
# ---------------------------------------------------------------------------


class TestTargetMath:
    def test_pdiff1_constant(self):
        assert PDIFF1_TARGET_INT == (1 << 224) - 1

    def test_difficulty_one_is_pdiff1(self):
        assert difficulty_to_target_int(1.0) == PDIFF1_TARGET_INT

    def test_non_finite_fails_closed(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            assert difficulty_to_target_int(bad) == 0

    def test_non_positive_is_accept_all_sentinel(self):
        assert difficulty_to_target_int(0.0) == (1 << 256) - 1
        assert difficulty_to_target_int(-1.0) == (1 << 256) - 1

    def test_sub_one_scales_wider_than_pdiff1(self):
        # documented stub divergence: the production client clamps <=1.0 to
        # pdiff1; the stub scales so host scenarios can find shares fast.
        # (float division: (2^224-1) rounds to 2^224, so the exact product is
        # within +-1 ulp of 2^225 — assert the relation, not the last bit)
        wide = difficulty_to_target_int(0.5)
        assert PDIFF1_TARGET_INT < wide <= (1 << 225)
        assert difficulty_to_target_int(0.25) > wide

    def test_monotone_harder_difficulty_never_easier_target(self):
        diffs = [1e-5, 1e-4, 0.5, 1.0, 2.0, 16.0, 4096.0, 1e6]
        targets = [difficulty_to_target_int(d) for d in diffs]
        for easier, harder in zip(targets, targets[1:]):
            assert harder <= easier

    def test_meets_target_is_bigendian_lte(self):
        target = target_int_to_bytes(0x0102)  # 32-byte BE: ...00 01 02
        assert meets_target(bytes(30) + b"\x01\x01", target)
        assert meets_target(bytes(30) + b"\x01\x02", target)
        assert not meets_target(bytes(30) + b"\x01\x03", target)
        assert not meets_target(bytes(29) + b"\x01\x00\x00", target)


# ---------------------------------------------------------------------------
# Header construction helpers (mirror of job.rs / work.rs)
# ---------------------------------------------------------------------------


class TestHeaderMath:
    def test_reverse_words_per_4(self):
        assert reverse_words_per_4(bytes.fromhex("aabbccdd")) == bytes.fromhex("ddccbbaa")
        assert reverse_words_per_4(b"") == b""
        with pytest.raises(ValueError):
            reverse_words_per_4(b"\x00" * 3)

    def test_merkle_fold_matches_job_rs_semantics(self):
        # current = sha256d(current || branch), raw byte order, per job.rs
        coinbase_hash = bytes(range(32))
        branch = bytes(range(32, 64))
        expected = sha256d(coinbase_hash + branch)
        assert merkle_root(coinbase_hash, [branch]) == expected

    def test_header_layout_is_80_bytes_le_fields(self):
        import struct

        header = build_header(
            0x20000000, bytes(32), bytes(32), 0x66112233, 0x1D00FFFF, 0xAABBCCDD
        )
        assert len(header) == 80
        assert header[0:4] == struct.pack("<I", 0x20000000)
        assert header[68:72] == struct.pack("<I", 0x66112233)
        assert header[72:76] == struct.pack("<I", 0x1D00FFFF)
        assert header[76:80] == struct.pack("<I", 0xAABBCCDD)


# ---------------------------------------------------------------------------
# Wire behavior end-to-end over a real socket
# ---------------------------------------------------------------------------


class LineClient:
    """Minimal JSON-lines TCP client for talking to the stub directly."""

    def __init__(self, port: int, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()
        self._id = 0

    def close(self) -> None:
        self.sock.close()

    def request(self, method: str, params: list) -> dict:
        self._id += 1
        line = json.dumps({"id": self._id, "method": method, "params": params})
        self.sock.sendall((line + "\n").encode())
        return self.wait_for_id(self._id)

    def wait_for_id(self, request_id: int) -> dict:
        while True:
            message = self.read_message()
            if message.get("id") == request_id:
                return message

    def read_message(self) -> dict:
        while True:
            if b"\n" in self._buf:
                raw, _, rest = self._buf.partition(b"\n")
                self._buf = bytearray(rest)
                text = raw.decode().strip()
                if text:
                    return json.loads(text)
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("stub closed")
            self._buf.extend(chunk)

    def send_raw(self, text: str) -> None:
        self.sock.sendall((text + "\n").encode())


@pytest.fixture()
def stub():
    server = StratumStub(difficulty=TEST_DIFFICULTY, seed=0xABCD).start()
    yield server
    server.stop()


class TestHandshakeShapes:
    def test_subscribe_result_shape(self, stub):
        client = LineClient(stub.port)
        try:
            response = client.request("mining.subscribe", ["pytest/0.1"])
            result = response["result"]
            assert response["error"] is None
            assert isinstance(result, list) and len(result) == 3
            # result[1] = extranonce1 hex (session id), result[2] = en2 size
            extranonce1 = bytes.fromhex(result[1])
            assert len(extranonce1) >= 4
            assert result[2] == 4
        finally:
            client.close()

    def test_authorize_streams_difficulty_then_notify(self, stub):
        client = LineClient(stub.port)
        try:
            client.request("mining.subscribe", ["pytest/0.1"])
            auth = client.request("mining.authorize", ["twin.worker", "x"])
            assert auth["result"] is True
            difficulty = client.read_message()
            assert difficulty["method"] == "mining.set_difficulty"
            assert difficulty["params"] == [TEST_DIFFICULTY]
            notify = client.read_message()
            assert notify["method"] == "mining.notify"
            params = notify["params"]
            assert len(params) == 9  # client parser requires exactly these 9
            assert isinstance(params[8], bool)
            assert len(params[1]) == 64  # prev_hash hex (32 bytes)
            assert len(params[6]) == 8  # nbits
            assert len(params[7]) == 8  # ntime
        finally:
            client.close()

    def test_configure_and_extensions_answered(self, stub):
        client = LineClient(stub.port)
        try:
            configure = client.request(
                "mining.configure", [["version-rolling", "subscribe-extranonce"], {}]
            )
            result = configure["result"]
            assert result["version-rolling"] is True
            assert result["version-rolling.mask"] == "1fffe000"
            assert client.request("mining.extranonce.subscribe", [])["result"] is True
            pong = client.request("mining.ping", [])
            assert pong["result"] is None
            version = client.request("client.get_version", [])
            assert "emu-twin-stratum-stub" in version["result"]
        finally:
            client.close()

    def test_invalid_json_lines_are_ignored_not_fatal(self, stub):
        client = LineClient(stub.port)
        try:
            client.send_raw("this is not json")
            client.send_raw("")
            response = client.request("mining.subscribe", ["pytest/0.1"])
            assert isinstance(response["result"], list)
        finally:
            client.close()


class TestShareValidation:
    def test_stub_issues_job_and_validates_self_computed_share(self, stub):
        """The core contract: stub issues a job; the test finds a share with
        REAL sha256d; the stub re-validates by recomputation and accepts."""
        client = LineClient(stub.port)
        try:
            subscribe = client.request("mining.subscribe", ["pytest/0.1"])
            extranonce1 = bytes.fromhex(subscribe["result"][1])
            client.request("mining.authorize", ["twin.worker", "x"])
            difficulty_msg = client.read_message()
            assert difficulty_msg["params"] == [stub.difficulty]
            notify = client.read_message()
            job_id = notify["params"][0]

            job = stub.get_job(job_id)
            assert job is not None, "stub must track every job it issued"

            share = find_share(
                job,
                extranonce1,
                difficulty=stub.difficulty,
                max_attempts=2_000_000,
                timeout_secs=60.0,
            )
            assert share is not None, "real-sha256d search must find a low-diff share"

            response = client.request(
                "mining.submit",
                [
                    "twin.worker",
                    job_id,
                    share["extranonce2_hex"],
                    share["ntime_hex"],
                    share["nonce_hex"],
                ],
            )
            assert response["result"] is True, response
            assert response["error"] is None

            stats = stub.stats()
            assert stats["accepted"] == 1
            assert stats["rejected"] == 0
            record = stats["shares"][-1]
            assert record["share_hash"] == share["hash_hex"]
            # the stub really recomputed: the stored hash must equal sha256d
            # of the stored reconstructed header
            recomputed = sha256d(bytes.fromhex(record["header_hex"]))
            assert recomputed.hex() == record["share_hash"]
            assert recomputed <= bytes.fromhex(record["target"])
            assert stats["latency_ms"]["last"] is not None
        finally:
            client.close()

    def test_garbage_nonce_rejected_as_above_target(self, stub):
        client = LineClient(stub.port)
        try:
            subscribe = client.request("mining.subscribe", ["pytest/0.1"])
            client.request("mining.authorize", ["twin.worker", "x"])
            client.read_message()  # set_difficulty
            notify = client.read_message()
            job_id, ntime = notify["params"][0], notify["params"][7]

            response = client.request(
                "mining.submit",
                ["twin.worker", job_id, "00000000", ntime, "deadbeef"],
            )
            assert response["result"] is False
            error = response["error"]
            assert error[1] == "share-hash-above-target"
            stats = stub.stats()
            assert stats["rejected"] == 1 and stats["accepted"] == 0
        finally:
            client.close()

    def test_unknown_job_rejected(self, stub):
        client = LineClient(stub.port)
        try:
            client.request("mining.subscribe", ["pytest/0.1"])
            client.request("mining.authorize", ["twin.worker", "x"])
            client.read_message()
            client.read_message()
            response = client.request(
                "mining.submit", ["twin.worker", "nope", "00000000", "00000000", "00000000"]
            )
            assert response["result"] is False
            assert response["error"][1] == "unknown-job"
        finally:
            client.close()

    def test_version_bits_param_with_zero_value_still_valid(self, stub):
        """6-param submit with all-zero version bits must behave identically
        to the 5-param form (daemon appends the field only when rolling)."""
        client = LineClient(stub.port)
        try:
            subscribe = client.request("mining.subscribe", ["pytest/0.1"])
            extranonce1 = bytes.fromhex(subscribe["result"][1])
            client.request("mining.authorize", ["twin.worker", "x"])
            client.read_message()
            notify = client.read_message()
            job_id = notify["params"][0]
            job = stub.get_job(job_id)
            share = find_share(job, extranonce1, stub.difficulty, max_attempts=2_000_000)
            assert share is not None
            response = client.request(
                "mining.submit",
                [
                    "twin.worker",
                    job_id,
                    share["extranonce2_hex"],
                    share["ntime_hex"],
                    share["nonce_hex"],
                    "00000000",
                ],
            )
            assert response["result"] is True
        finally:
            client.close()


class TestJobFactory:
    def test_jobs_are_deterministic(self):
        first = make_job(3, ntime=0x66112233)
        second = make_job(3, ntime=0x66112233)
        assert first.describe() == second.describe()

    def test_jobs_differ_per_index(self):
        assert make_job(1).prev_hash_hex != make_job(2).prev_hash_hex


class TestStatsAndLifecycle:
    def test_issue_job_pushes_to_authorized_sessions(self, stub):
        client = LineClient(stub.port)
        try:
            client.request("mining.subscribe", ["pytest/0.1"])
            client.request("mining.authorize", ["twin.worker", "x"])
            client.read_message()
            client.read_message()
            job = stub.issue_job(ntime=0x77889900)
            notify = client.read_message()
            assert notify["method"] == "mining.notify"
            assert notify["params"][0] == job.job_id
            assert notify["params"][7] == "77889900"
            assert stub.stats()["jobs_issued"] == 2
        finally:
            client.close()

    def test_difficulty_must_be_finite_positive(self):
        with pytest.raises(ValueError):
            StratumStub(difficulty=0.0)
        with pytest.raises(ValueError):
            StratumStub(difficulty=float("inf"))
