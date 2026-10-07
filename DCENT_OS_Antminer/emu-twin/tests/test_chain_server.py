"""Chain-server tests: the full mini-loop, host-side.

The loop: connect over localhost TCP -> ChainInactive -> SetAddress ladder
-> GetAddress roster (unique parseable responses) -> register writes (PLL /
TicketMask / FastUART baud ladder) -> dispatch a job frame -> the chain
finds a REAL valid share (low target) -> the nonce response parses -> the
share meets the target when sha256d is recomputed independently.

G-invariant spirit: a dedicated test asserts no code path opens real device
files (/dev/*, Windows device namespaces) during a live session.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import hashlib
import random
import socket
import struct
import time

import pytest

import chain_server as cs
import nonce_engine as ne
import physics as phys
import protocol as wire

N_CHIPS = 4
DIFFICULTY = 2e-5          # low target: found-share rate, not terahash
MAX_NONCES = 1 << 18       # bounded per-chip window (~1-2 s Python)


def _fields(job_id: int = 24) -> wire.JobFields:
    rng = random.Random(0xD1CE + job_id)
    return wire.JobFields(
        job_id=job_id,
        num_midstates=1,
        starting_nonce=0,
        nbits=0x1D00_FFFF,
        ntime=0x6802_AB6E,
        merkle_root=bytes(rng.randrange(256) for _ in range(32)),
        prev_block_hash=bytes(rng.randrange(256) for _ in range(32)),
        version=0x2000_0000,
    )


class Client:
    """Tiny test client: send frames, read exact-size responses."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.buf = bytearray()

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def read(self, n: int, timeout: float = 10.0) -> bytes:
        """Read up to n bytes; returns short on timeout/close (never raises
        on timeout so 'no response' cases are testable)."""
        deadline = time.monotonic() + timeout
        while len(self.buf) < n and time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf.extend(chunk)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def close(self) -> None:
        self.sock.close()


@pytest.fixture()
def server():
    chain = cs.SimChain(
        n_chips=N_CHIPS,
        difficulty=DIFFICULTY,
        max_nonces_per_job=MAX_NONCES,
        hw_error_injection=False,  # happy path; injection has its own test
    )
    srv = cs.ChainServer(chain, host="127.0.0.1", port=0)
    srv.start()
    try:
        yield srv
    finally:
        srv.close()


class TestEnumeration:
    def test_inactive_ladder_getaddress_roster(self, server):
        client = Client(server.port)
        try:
            # 1. ChainInactive broadcast: no responses, addresses wiped
            client.send(wire.chain_inactive_frame())
            # 2. SetAddress ladder: stride 2, first un-addressed chip claims
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            # 3. GetAddress broadcast: every chip answers, in chain order
            client.send(wire.get_address_frame())
            seen = []
            for _ in range(N_CHIPS):
                frame = client.read(wire.BM136X_RESPONSE_WIRE_BYTES)
                parsed = wire.parse_register_response(frame)
                seen.append(parsed.responder_address)
                assert parsed.chip_id == wire.BM1362_CHIP_ID
                assert parsed.core_count_encoding == 0x03
                assert parsed.reg == wire.REG_CHIP_ADDRESS
                assert parsed.register_value == (
                    (wire.BM1362_CHIP_ID << 16) | (0x03 << 8)
                    | parsed.responder_address
                )
            assert seen == [0, 2, 4, 6]
        finally:
            client.close()

    def test_inactive_resets_addresses(self, server):
        client = Client(server.port)
        try:
            client.send(wire.chain_inactive_frame())
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            client.send(wire.chain_inactive_frame())
            client.send(wire.get_address_frame())
            # nothing answers until re-addressed: short read window
            assert client.read(1, timeout=0.5) == b""
        finally:
            client.close()

    def test_ladder_is_serialized_first_unassigned_claims(self, server):
        chain = server.chain
        chain.chain_inactive()
        assert chain.set_chip_address(0)
        assert chain.set_chip_address(2)
        assert [c.address for c in chain.chips[:2]] == [0, 2]
        # extras beyond chip count return False
        for i in range(N_CHIPS):
            chain.set_chip_address(i)
        assert not chain.set_chip_address(0xFE)


class TestRegistersAndBaud:
    def test_pll_write_reflected_in_readback_and_freq(self, server):
        client = Client(server.port)
        try:
            client.send(wire.chain_inactive_frame())
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            # nameplate PLL: FBDIV=218, REFDIV=1, postdiv 0x41 -> 545 MHz
            reg_545 = (0x40 << 24) | (218 << 16) | (0x01 << 8) | 0x41
            client.send(
                wire.broadcast_write_frame(wire.REG_PLL0, reg_545)
            )
            client.send(wire.single_read_frame(2, wire.REG_PLL0))
            frame = client.read(wire.BM136X_RESPONSE_WIRE_BYTES)
            parsed = wire.parse_register_response(frame)
            assert parsed.responder_address == 2
            assert parsed.register_value == reg_545
            assert server.chain.chips[1].freq_mhz == 545.0
        finally:
            client.close()

    def test_fastuart_baud_ladder(self, server):
        chain = server.chain
        chain.chain_inactive()
        for i in range(N_CHIPS):
            chain.set_chip_address(i * 2)
        assert chain.baud == wire.DEFAULT_BAUD
        chain.broadcast_write(
            wire.REG_FAST_UART_CONFIG, wire.FAST_UART_CONFIG_VALUE
        )
        assert chain.baud == wire.OPERATIONAL_BAUD
        chain.broadcast_write(wire.REG_FAST_UART_CONFIG, 0)
        assert chain.baud == wire.DEFAULT_BAUD

    def test_ticket_mask_broadcast_writes_all_chips(self, server):
        chain = server.chain
        chain.chain_inactive()
        for i in range(N_CHIPS):
            chain.set_chip_address(i * 2)
        chain.broadcast_write(wire.REG_TICKET_MASK, 0x1FF)
        for chip in chain.assigned_chips():
            assert chip.registers[wire.REG_TICKET_MASK] == 0x1FF


class TestMiniMiningLoop:
    def test_dispatch_job_returns_real_share_that_meets_target(self, server):
        client = Client(server.port)
        try:
            # admission flow
            client.send(wire.chain_inactive_frame())
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            # job dispatch (direct form, deterministic fields)
            fields = _fields(job_id=24)
            client.send(wire.build_job_frame(fields))
            target = ne.target_from_difficulty(DIFFICULTY)
            got_any = False
            # one 11-byte response per searching chip that found a share
            for _ in range(N_CHIPS):
                frame = client.read(
                    wire.BM136X_RESPONSE_WIRE_BYTES, timeout=15.0
                )
                if len(frame) < wire.BM136X_RESPONSE_WIRE_BYTES:
                    break
                parsed = wire.parse_nonce_response(frame)
                assert parsed.is_job_response
                assert parsed.job_id == 24  # JOB_ID_INCREMENT ladder echo
                # INDEPENDENT recompute: full header, plain hashlib
                header80 = fields.header_prefix() + struct.pack(
                    "<I", parsed.nonce
                )
                digest = hashlib.sha256(
                    hashlib.sha256(header80).digest()
                ).digest()
                le = int.from_bytes(digest, "big")
                assert le <= target, (
                    f"nonce {parsed.nonce:#x} does not meet the target"
                )
                got_any = True
            assert got_any, "no searching chip found a share in the window"
        finally:
            client.close()

    def test_job_id_echo_ladder(self, server):
        # JOB_ID_INCREMENT=24 keeps the [6:3] echo unique within 16 dispatches
        chain = server.chain
        chain.chain_inactive()
        for i in range(N_CHIPS):
            chain.set_chip_address(i * 2)
        for step in range(4):
            job_id = (step * wire.JOB_ID_INCREMENT) & wire.JOB_ID_MASK
            fields = _fields(job_id=job_id)
            responses = chain.dispatch_job(fields)
            assert responses, "expected at least one share response"
            for frame in responses:
                parsed = wire.parse_nonce_response(frame)
                assert parsed.job_id == job_id


class TestHwErrorInjection:
    def test_chip_past_its_cliff_returns_failing_nonce(self):
        # bins with the cliff far BELOW the operating point -> error ~1 ->
        # every returned nonce fails daemon-side validation
        bins = [
            phys.ChipBin(
                "weak", 0.8, 400.0, 0.5, "[DCENT-MODEL] weak bin test"
            )
        ]
        chain = cs.SimChain(
            n_chips=2,
            difficulty=DIFFICULTY,
            max_nonces_per_job=MAX_NONCES,
            bins=bins,
            hw_error_injection=True,
        )
        chain.chain_inactive()
        for i in range(2):
            chain.set_chip_address(i * 2)
        chain.broadcast_write(
            wire.REG_PLL0, (0x40 << 24) | (218 << 16) | (0x01 << 8) | 0x41
        )
        assert chain.chips[0].freq_mhz == 545.0
        responses = chain.dispatch_job(_fields(job_id=0))
        assert responses
        target = ne.target_from_difficulty(DIFFICULTY)
        prefix = _fields(job_id=0).header_prefix()
        saw_corrupt = False
        for frame in responses:
            parsed = wire.parse_nonce_response(frame)
            header80 = prefix + struct.pack("<I", parsed.nonce)
            digest = hashlib.sha256(
                hashlib.sha256(header80).digest()
            ).digest()
            if int.from_bytes(digest, "big") > target:
                saw_corrupt = True
        assert saw_corrupt, "weak-bin chip must inject HW errors"
        assert sum(c.hw_errors_injected for c in chain.chips) >= 1

    def test_healthy_chip_errors_stay_rare(self, server):
        # nameplate bins: cliff ~560+/-6 MHz vs 545 MHz operation on a cool
        # die -> error rate ~1e-3 or less per share
        chain = server.chain
        rate = chain.chips[0].error_rate(chain.chip_die_temps()[0])
        assert rate < 1e-3


class TestStatusAndConfig:
    def test_status_reports_model_outputs_with_tier_label(self, server):
        status = server.chain.status()
        assert status["n_chips"] == N_CHIPS
        assert status["assigned"] == 0
        assert status["baud"] == wire.DEFAULT_BAUD
        assert "T1-sim" in status["tier"]

    def test_set_rail(self, server):
        server.chain.set_rail(12.45)
        assert server.chain.rail_v == 12.45
        with pytest.raises(ValueError):
            server.chain.set_rail(0)

    def test_loopback_only_policy(self):
        chain = cs.SimChain(n_chips=1)
        with pytest.raises(ValueError):
            cs.ChainServer(chain, host="0.0.0.0", port=0)


class TestGInvariantNoDevices:
    """G-spirit: the emulator must never open a real device file."""

    def test_guard_path_rejects_device_namespaces(self):
        for bad in (
            "/dev/ttyS2",
            "/dev/i2c-1",
            "/dev/mem",
            "\\\\.\\COM3",
            "\\\\?\\Volume{...}",
        ):
            with pytest.raises(PermissionError):
                cs._guard_path(bad)

    def test_guard_path_allows_normal_files(self, tmp_path):
        ok = str(tmp_path / "status.log")
        assert cs._guard_path(ok) == ok

    def test_status_log_opens_through_guard(self, tmp_path):
        log_path = tmp_path / "emu-status.log"
        handle = cs.open_status_log(str(log_path))
        try:
            assert handle is not None
            handle.write("ok\n")
        finally:
            handle.close()
        assert log_path.read_text(encoding="utf-8") == "ok\n"
        assert cs.open_status_log(None) is None

    def test_live_session_never_opens_device_files(self, server, monkeypatch):
        """Run a full enumeration session with builtins.open patched to
        explode on any device-like path — proving no code path touches
        real hardware."""
        import builtins
        import re

        real_open = builtins.open

        def guarded_open(file, *args, **kwargs):
            name = str(file).replace("\\", "/").lower()
            if name.startswith(("/dev/", "//./", "//?/")) or re.match(
                r"^com\d", name
            ):
                raise AssertionError(f"device path opened: {file!r}")
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)
        client = Client(server.port)
        try:
            client.send(wire.chain_inactive_frame())
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            client.send(wire.get_address_frame())
            for _ in range(N_CHIPS):
                frame = client.read(wire.BM136X_RESPONSE_WIRE_BYTES)
                assert wire.parse_register_response(frame).chip_id == 0x1362
        finally:
            client.close()


class TestResync:
    def test_idle_padding_and_garbage_are_skipped(self, server):
        client = Client(server.port)
        try:
            client.send(b"\x00\x00\xFF\x13")  # idle + garbage
            client.send(wire.chain_inactive_frame())
            for i in range(N_CHIPS):
                client.send(wire.set_chip_address_frame(i * 2))
            client.send(wire.get_address_frame())
            expected = N_CHIPS * wire.BM136X_RESPONSE_WIRE_BYTES
            frames = client.read(expected, timeout=15.0)
            assert len(frames) == expected
            for i in range(N_CHIPS):
                parsed = wire.parse_register_response(
                    frames[
                        i * 11 : (i + 1) * 11
                    ]
                )
                assert parsed.responder_address == i * 2
        finally:
            client.close()
