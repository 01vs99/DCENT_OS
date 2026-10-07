"""Wire-framing tests: CRC vectors, frame round-trips, and pinned constants.

Oracle-fixture policy: vectors lifted from the in-tree Rust test suites are
labeled [DCENT-in-tree] and cite their source file; where no retained vector
exists, the test computes the expected value from an INDEPENDENT local
implementation of the algorithm and asserts cross-consistency with the
module under test (two derivations agreeing is the check).

Sources:
  - dcentrald-asic/src/protocol.rs (tests: response CRC5 vectors)
  - dcentrald-asic/src/bm1362/mod.rs (pinned frame builder bytes)
  - dcentrald-api-types/src/asic_protocol_spec.rs (response geometry)

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import random
import struct

import pytest

import protocol as wire


# ---------------------------------------------------------------------------
# Independent CRC implementations (cross-consistency oracles)
# ---------------------------------------------------------------------------


def crc5_reference(data: bytes) -> int:
    """Independent byte-at-a-time table implementation of the command CRC-5
    (poly 0x05, init 0x1F, MSB-first).

    Structurally different from the module's bit-loop: a (state, byte)
    transition table built once by unrolling the recurrence over all 32
    register states x 256 byte values, then chained one byte at a time.
    Catches loop-order/bit-order/indexing mistakes in either implementation.
    """
    table = {}
    for state in range(32):
        for byte in range(256):
            r = state
            for bit_index in range(7, -1, -1):
                data_bit = (byte >> bit_index) & 1
                top = (r >> 4) & 1
                r = (r << 1) & 0x1F
                if data_bit ^ top:
                    r ^= 0x05
            table[(state, byte)] = r
    crc = 0x1F
    for byte in data:
        crc = table[(crc, byte)]
    return crc


def crc16_reference(data: bytes) -> int:
    """Independent CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def response_crc5_reference(data: bytes, init: int = 0x03) -> int:
    """Independent re-derivation of the modified response state machine
    using a nibble-step table-free formulation (same transitions, written
    from the VHDL description rather than copied from protocol.py)."""
    c0, c1, c2, c3, c4 = (
        init & 1,
        (init >> 1) & 1,
        (init >> 2) & 1,
        (init >> 3) & 1,
        (init >> 4) & 1,
    )
    for byte in data:
        for bit_index in range(7, -1, -1):
            data_bit = (byte >> bit_index) & 1
            feedback = data_bit ^ c4
            # c4' = c3; c3' = c2 ^ data_bit; c2' = c1 ^ feedback;
            # c1' = c0; c0' = feedback
            c0, c1, c2, c3, c4 = (
                feedback,
                c0,
                c1 ^ feedback,
                c2 ^ data_bit,
                c3,
            )
    return c4 << 4 | c3 << 3 | c2 << 2 | c1 << 1 | c0


# ---------------------------------------------------------------------------
# CRC-5 (command direction)
# ---------------------------------------------------------------------------


class TestCrc5:
    def test_matches_independent_implementation_over_corpus(self):
        rng = random.Random(0x5A)
        for length in range(0, 33):
            for _ in range(8):
                data = bytes(rng.randrange(256) for _ in range(length))
                assert wire.crc5(data) == crc5_reference(data), data.hex()

    def test_empty_input_returns_init_register(self):
        assert wire.crc5(b"") == 0x1F

    def test_in_tree_literal_get_address_body(self):
        # [DCENT-in-tree] retained literal:
        #   s19k_bm1366_uart_rx.rs:2368  esp_asic_crc5(&[0x52,0x05,0x00,0x00]) == 0x0A
        #   stock_fpga_policy.rs:1971   stock_bitmain_crc5(&[0x52,0x05,0x00,0x00], 32) == 0x0A
        # (GetAddress body — a true known-answer oracle, not a cross-check)
        assert wire.crc5(bytes([0x52, 0x05, 0x00, 0x00])) == 0x0A

    def test_pinned_chain_inactive_crc(self):
        # [DCENT-in-tree] bm1362/mod.rs: ChainInactive body [53 05 00 00]
        frame = wire.chain_inactive_frame()
        assert frame[2:6] == bytes([0x53, 0x05, 0x00, 0x00])
        assert frame[6] == wire.crc5(frame[2:6])
        assert frame[6] == crc5_reference(frame[2:6])

    def test_stream_composable(self):
        rng = random.Random(2)
        for _ in range(16):
            a = bytes(rng.randrange(256) for _ in range(rng.randrange(9)))
            b = bytes(rng.randrange(256) for _ in range(rng.randrange(9)))
            state_a = wire.crc5(a)
            resumed = _crc5_resume(b, state_a)
            assert wire.crc5(a + b) == resumed


def _crc5_resume(data: bytes, state: int) -> int:
    """Resume the command CRC-5 register at `state` over `data`
    (same recurrence, different entry point)."""
    crc = state & 0x1F
    for byte in data:
        for bit_index in range(7, -1, -1):
            data_bit = (byte >> bit_index) & 1
            top = (crc >> 4) & 1
            crc = (crc << 1) & 0x1F
            if data_bit ^ top:
                crc ^= 0x05
    return crc


# ---------------------------------------------------------------------------
# Response CRC-5 (modified state machine, init 0x03)
# ---------------------------------------------------------------------------


class TestResponseCrc5:
    # [DCENT-in-tree] protocol.rs test
    # bm13xx_command_response_crc5_matches_all_retained_contract_vectors
    # (source contract: contracts/asic-wire/v1/bm13xx-response-crc5.json)
    RETAINED_VECTORS = [
        (bytes([0x13, 0x97, 0x18, 0x00, 0x00, 0x00]), 0x06),
        (bytes([0x13, 0x62, 0x03, 0x00, 0x00, 0x00]), 0x0D),
        (bytes([0x13, 0x62, 0x03, 0xCA, 0xCA, 0x00, 0x00, 0x00]), 0x08),
        (bytes([0x13, 0x62, 0x03, 0xCC, 0xCC, 0x00, 0x00, 0x00]), 0x12),
        (bytes([0x13, 0x62, 0x03, 0xF4, 0xF4, 0x00, 0x00, 0x00]), 0x02),
        (bytes([0x13, 0x62, 0x03, 0xF6, 0xF6, 0x00, 0x00, 0x00]), 0x17),
        (bytes([0x13, 0x62, 0x03, 0xF8, 0xF8, 0x00, 0x00, 0x00]), 0x13),
        (bytes([0x13, 0x62, 0x03, 0xFA, 0xFA, 0x00, 0x00, 0x00]), 0x06),
    ]

    @pytest.mark.parametrize("payload,expected", RETAINED_VECTORS)
    def test_retained_contract_vectors(self, payload, expected):
        assert wire.response_crc5(payload) == expected

    def test_empty_input_returns_init_state(self):
        # [DCENT-in-tree] protocol.rs: crc of empty payload == init 0x03
        assert wire.response_crc5(b"") == 0x03

    def test_matches_independent_derivation_over_corpus(self):
        rng = random.Random(0x03)
        for length in range(0, 17):
            for _ in range(8):
                data = bytes(rng.randrange(256) for _ in range(length))
                assert wire.response_crc5(data) == response_crc5_reference(data)

    def test_stream_composable(self):
        # [DCENT-in-tree] protocol.rs stream-composability property
        rng = random.Random(1)
        for _ in range(16):
            a = bytes(rng.randrange(256) for _ in range(rng.randrange(9)))
            b = bytes(rng.randrange(256) for _ in range(rng.randrange(9)))
            state_a = wire.response_crc5(a)
            joined = wire.response_crc5(a + b)
            # resume the state machine at state_a over b
            resumed = wire.response_crc5(b, init=state_a)
            assert joined == resumed

    def test_detects_single_bit_mutations(self):
        # [DCENT-in-tree] protocol.rs mutation-detection property
        for payload, _ in self.RETAINED_VECTORS[:3]:
            expected = wire.response_crc5(payload)
            for bit in range(len(payload) * 8):
                mutated = bytearray(payload)
                mutated[bit // 8] ^= 1 << (bit % 8)
                assert wire.response_crc5(bytes(mutated)) != expected


# ---------------------------------------------------------------------------
# CRC-16 CCITT-FALSE (job direction)
# ---------------------------------------------------------------------------


class TestCrc16:
    def test_known_check_value(self):
        # [PUBLIC-STANDARD] CRC-16/CCITT-FALSE check value for "123456789"
        assert wire.crc16(b"123456789") == 0x29B1

    def test_matches_independent_implementation(self):
        rng = random.Random(0x1021)
        for length in range(0, 97, 7):
            data = bytes(rng.randrange(256) for _ in range(length))
            assert wire.crc16(data) == crc16_reference(data)


# ---------------------------------------------------------------------------
# Constants vs protocol.rs / asic_protocol_spec.rs
# ---------------------------------------------------------------------------


class TestConstants:
    def test_header_encoding_constants(self):
        assert wire.TYPE_CMD == 0x40
        assert wire.TYPE_JOB == 0x20
        assert wire.GROUP_ALL == 0x10
        assert wire.CMD_SETADDR == 0x01
        assert wire.CMD_WRITE == 0x01
        assert wire.CMD_READ == 0x04
        assert wire.CMD_INACTIVE == 0x05
        assert wire.CMD_SETCONFIG == 0x08
        # combined headers
        assert wire.HDR_CMD_SETADDR == 0x41
        assert wire.HDR_CMD_WRITE == 0x41
        assert wire.HDR_CMD_READ == 0x44
        assert wire.HDR_CMD_SETCONFIG == 0x48
        assert wire.HDR_CMD_BCAST_WRITE == 0x51
        assert wire.HDR_CMD_BCAST_READ == 0x54
        assert wire.HDR_CMD_BCAST_SETCONFIG == 0x58
        assert wire.HDR_CMD_BCAST_INACTIVE == 0x55
        assert wire.HDR_JOB_WRITE == 0x21

    def test_response_geometry(self):
        # [DCENT-in-tree] asic_protocol_spec.rs
        assert wire.BM136X_RESPONSE_BODY_BYTES == 9
        assert wire.BM139X_RESPONSE_BODY_BYTES == 7
        assert wire.BM1387_RESPONSE_BODY_BYTES == 7
        assert wire.BM136X_RESPONSE_WIRE_BYTES == 11  # BM1362 nonce frame
        assert wire.BM139X_RESPONSE_WIRE_BYTES == 9

    def test_job_and_baud_constants(self):
        assert wire.JOB_ID_INCREMENT == 24
        assert wire.JOB_ID_MASK == 0x7F
        assert wire.DEFAULT_BAUD == 115_200
        assert wire.OPERATIONAL_BAUD == 3_125_000
        assert wire.BAUD_LADDER == (115_200, 3_125_000)
        assert wire.JOB_FRAME_WIRE_BYTES == 88
        assert wire.JOB_PAYLOAD_BYTES == 82

    def test_bm1362_chip_constants(self):
        assert wire.BM1362_CHIP_ID == 0x1362
        assert wire.BM1362_CORE_COUNT_ENCODING == 0x03
        assert wire.BM1362_CHIPS_PER_CHAIN == 126
        assert wire.BM1362_ADDRESS_INTERVAL == 2


# ---------------------------------------------------------------------------
# Command frame builders + parser round-trips
# ---------------------------------------------------------------------------


class TestCmdFrames:
    def test_pinned_builder_bytes(self):
        # [DCENT-in-tree] bm1362/mod.rs pinned pre-CRC bodies
        assert wire.get_address_frame()[2:6] == bytes([0x52, 0x05, 0x00, 0x00])
        assert wire.chain_inactive_frame()[2:6] == bytes([0x53, 0x05, 0x00, 0x00])
        assert wire.set_chip_address_frame(0x02)[2:6] == bytes(
            [0x40, 0x05, 0x02, 0x00]
        )
        # cold_boot_step: broadcast write reg 0x28 = 0x00003011
        # pre-CRC: [51 09 00 28 00 00 30 11]
        f = wire.broadcast_write_frame(0x28, 0x0000_3011)
        assert f[2:10] == bytes(
            [0x51, 0x09, 0x00, 0x28, 0x00, 0x00, 0x30, 0x11]
        )
        assert f[10] == wire.crc5(f[2:10])
        assert len(f) == 11  # 2 preamble + 9 body

    def test_bm1387_variants(self):
        # protocol.rs: BM1387 chain inactive 0x55, get address 0x54
        assert wire.chain_inactive_frame_bm1387()[2] == 0x55
        assert wire.get_address_frame_bm1387()[2] == 0x54

    def test_parse_round_trip(self):
        for frame in (
            wire.chain_inactive_frame(),
            wire.get_address_frame(),
            wire.set_chip_address_frame(6),
            wire.broadcast_write_frame(wire.REG_TICKET_MASK, 0xFF),
            wire.single_write_frame(4, wire.REG_PLL0, 0x40A8_0265),
            wire.single_read_frame(4, wire.REG_PLL0),
            wire.chain_inactive_frame_bm1387(),
            wire.get_address_frame_bm1387(),
        ):
            cmd = wire.parse_cmd_frame(frame)
            assert cmd.raw == frame
            assert cmd.header == frame[2]
            assert cmd.chip_addr == frame[4]
            assert cmd.reg == frame[5]
            if len(frame) == 11:  # 9-byte write body
                assert cmd.value == struct.unpack(">I", frame[6:10])[0]

    def test_parse_rejects_bad_crc(self):
        frame = bytearray(wire.get_address_frame())
        frame[4] ^= 0x01
        with pytest.raises(wire.ProtocolError):
            wire.parse_cmd_frame(bytes(frame))

    def test_parse_rejects_bad_preamble(self):
        with pytest.raises(wire.ProtocolError):
            wire.parse_cmd_frame(b"\x00\x00\x52\x05\x00\x00\x00")

    def test_length_byte_mismatch_rejected(self):
        frame = bytearray(wire.get_address_frame())
        frame[3] = 0x09  # claim 9-byte body on a 5-byte frame
        frame[6] = wire.crc5(bytes(frame[2:6]))
        with pytest.raises(wire.ProtocolError):
            wire.parse_cmd_frame(bytes(frame))

    def test_setaddr_vs_write_differentiated_by_length(self):
        setaddr = wire.parse_cmd_frame(wire.set_chip_address_frame(0x10))
        assert setaddr.is_setaddr
        write = wire.parse_cmd_frame(
            wire.single_write_frame(0x10, wire.REG_TICKET_MASK, 0xFF)
        )
        assert not write.is_setaddr
        assert write.value == 0xFF

    def test_frame_size_hint(self):
        assert wire.frame_size_hint(wire.get_address_frame()) == 7
        assert wire.frame_size_hint(wire.broadcast_write_frame(0x18, 1)) == 11
        job = wire.build_job_frame(_sample_fields())
        assert wire.frame_size_hint(job) == 88
        # incomplete buffer -> None-safe decidable cases
        assert wire.frame_size_hint(b"\x55") is None
        assert wire.frame_size_hint(b"\x00\x55") is None


# ---------------------------------------------------------------------------
# Job frames
# ---------------------------------------------------------------------------


def _sample_fields(job_id: int = 24) -> wire.JobFields:
    rng = random.Random(job_id)
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


class TestJobFrames:
    def test_round_trip(self):
        fields = _sample_fields()
        frame = wire.build_job_frame(fields)
        assert len(frame) == 88
        assert frame[:2] == b"\x55\xaa"
        assert frame[2] == 0x21
        assert frame[3] == 0x56  # proven BM1362 builder length byte
        parsed = wire.parse_job_frame(frame)
        assert parsed.job_id == fields.job_id
        assert parsed.nbits == fields.nbits
        assert parsed.ntime == fields.ntime
        assert parsed.version == fields.version
        assert parsed.merkle_root == fields.merkle_root
        assert parsed.prev_block_hash == fields.prev_block_hash

    def test_payload_layout(self):
        # [DCENT-in-tree] drivers/bm1362.rs build_serial_work_payload:
        # [0]=job_id [1]=1 [2:6]=start [6:10]=nbits LE [10:14]=ntime LE
        # [14:46]=merkle word-reversed [46:78]=prevhash word-reversed
        # [78:82]=version LE
        fields = _sample_fields()
        frame = wire.build_job_frame(fields)
        payload = frame[4:86]
        assert payload[0] == fields.job_id
        assert payload[1] == 0x01
        assert payload[2:6] == b"\x00\x00\x00\x00"
        assert payload[6:10] == struct.pack("<I", fields.nbits)
        assert payload[10:14] == struct.pack("<I", fields.ntime)
        assert payload[14:46] == _rev_words(fields.merkle_root)
        assert payload[46:78] == _rev_words(fields.prev_block_hash)
        assert payload[78:82] == struct.pack("<I", fields.version)

    def test_s19k_track1_length_byte_accepted(self):
        # serial_mining.rs: the S19k bosminer packer encodes the same
        # 88-byte frame with length byte 0x36
        frame = bytearray(wire.build_job_frame(_sample_fields()))
        frame[3] = 0x36
        # CRC does not cover the length byte?  It DOES (bytes 2:86), so
        # recompute after mutating:
        csum = wire.crc16(bytes(frame[2:86]))
        frame[86], frame[87] = csum >> 8, csum & 0xFF
        parsed = wire.parse_job_frame(bytes(frame))
        assert parsed.job_id == 24

    def test_unknown_length_byte_rejected(self):
        frame = bytearray(wire.build_job_frame(_sample_fields()))
        frame[3] = 0x42
        csum = wire.crc16(bytes(frame[2:86]))
        frame[86], frame[87] = csum >> 8, csum & 0xFF
        with pytest.raises(wire.ProtocolError):
            wire.parse_job_frame(bytes(frame))

    def test_crc_covers_header_through_payload(self):
        frame = bytearray(wire.build_job_frame(_sample_fields()))
        frame[10] ^= 0x01  # flip a payload bit
        with pytest.raises(wire.ProtocolError):
            wire.parse_job_frame(bytes(frame))
        frame2 = bytearray(wire.build_job_frame(_sample_fields()))
        frame2[2] ^= 0x01  # flip the header byte
        with pytest.raises(wire.ProtocolError):
            wire.parse_job_frame(bytes(frame2))


def _rev_words(data: bytes) -> bytes:
    out = bytearray(32)
    for i in range(8):
        out[i * 4 : i * 4 + 4] = data[(7 - i) * 4 : (7 - i) * 4 + 4]
    return bytes(out)


# ---------------------------------------------------------------------------
# Response frames
# ---------------------------------------------------------------------------


class TestRegisterResponse:
    def test_layout_matches_assigned_address_parser_law(self):
        # [DCENT-in-tree] bm1362/assigned_address.rs:
        # frame[2:4]=chip id BE, [4]=core count enc 0x03, [5]==[6]=addr,
        # [7]=reg 0x00, [8:10]=[0,0], [10]=trailer with cmd CRC5
        frame = wire.build_register_response(chip_addr=6, reg=0x00, value=0)
        assert len(frame) == 11
        assert frame[:2] == b"\xaa\x55"
        assert frame[2] == 0x13 and frame[3] == 0x62
        assert frame[4] == 0x03
        assert frame[5] == 6 and frame[6] == 6
        assert frame[7] == 0x00
        assert frame[8:10] == b"\x00\x00"
        parsed = wire.parse_register_response(frame)
        assert parsed.chip_id == 0x1362
        assert parsed.core_count_encoding == 0x03
        assert parsed.responder_address == 6
        assert parsed.register_value == 0x1362_0306

    def test_parser_rejects_job_trailer(self):
        frame = bytearray(wire.build_register_response(6, 0x00, 0))
        frame[10] |= 0x80
        with pytest.raises(wire.ProtocolError):
            wire.parse_register_response(bytes(frame))

    def test_parser_rejects_bad_crc(self):
        frame = bytearray(wire.build_register_response(6, 0x00, 0))
        frame[10] = (frame[10] & ~0x1F) | ((frame[10] + 1) & 0x1F)
        with pytest.raises(wire.ProtocolError):
            wire.parse_register_response(bytes(frame))


class TestNonceResponse:
    def test_round_trip_and_job_id_echo(self):
        # job_id echo law: only bits [6:3] round-trip, so the increment is
        # 24 (JOB_ID_INCREMENT) keeping the echo unique within 16 dispatches
        for job_id in (0, 24, 48, 72, 96, 120):
            frame = wire.build_nonce_response(
                nonce=0xDEAD_BEEF, job_id=job_id, version_bits=0x1F
            )
            assert len(frame) == 11
            parsed = wire.parse_nonce_response(frame)
            assert parsed.nonce == 0xDEAD_BEEF
            assert parsed.job_id == job_id
            assert parsed.is_job_response
            assert parsed.version_bits_raw == 0x1F
            assert parsed.small_core == 0

    def test_nonce_is_little_endian(self):
        # uart_transport.rs: nonce = u32::from_le_bytes of the 4 wire bytes
        frame = wire.build_nonce_response(nonce=0x0102_0304, job_id=0)
        assert frame[2:6] == bytes([0x04, 0x03, 0x02, 0x01])

    def test_version_bits_big_endian(self):
        frame = wire.build_nonce_response(nonce=1, job_id=0, version_bits=0x1234)
        assert frame[8:10] == bytes([0x12, 0x34])

    def test_rolled_version_reconstruction(self):
        #  am2 BM1362 BIP320 law (never re-introduce the guard):
        # rolled = (base & !0x1FFFE000) | ((vbits << 13) & 0x1FFFE000)
        parsed = wire.parse_nonce_response(
            wire.build_nonce_response(nonce=1, job_id=0, version_bits=0x0F)
        )
        base = 0x2000_0000
        rolled = parsed.rolled_version(base)
        assert rolled == (base & ~0x1FFFE000) | ((0x0F << 13) & 0x1FFFE000)

    def test_trailer_carries_response_crc5(self):
        payload_nonce_frame = wire.build_nonce_response(nonce=0xAB, job_id=24)
        # flags bits 4:0 must equal response_crc5 over the 8 payload bytes
        expected = wire.response_crc5(payload_nonce_frame[2:10])
        assert payload_nonce_frame[10] & 0x1F == expected & 0x1F


# ---------------------------------------------------------------------------
# PLL decode
# ---------------------------------------------------------------------------


class TestPllDecode:
    def test_re018_default_decodes_to_50_mhz(self):
        # drivers/bm1362.rs: RE-018 default 0x40A80265 -> 50 MHz
        assert wire.decode_pll_reg_to_freq_mhz(0x40A8_0265) == 50

    def test_nameplate_545(self):
        # FBDIV=218, REFDIV=1, postdiv 0x41 (pd1=5, pd2=2) -> 25*218/10=545
        reg = (0x40 << 24) | (218 << 16) | (0x01 << 8) | 0x41
        assert wire.decode_pll_reg_to_freq_mhz(reg) == 545

    def test_lock_bit_ignored(self):
        reg = (0x40 << 24) | (218 << 16) | (0x01 << 8) | 0x41
        assert wire.decode_pll_reg_to_freq_mhz(reg | wire.PLL_LOCK_BIT) == 545
