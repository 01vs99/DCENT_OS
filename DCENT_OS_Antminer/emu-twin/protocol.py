"""BM13xx serial-wire protocol: framing, CRCs, and byte-true constants.

Host-side mirror of `dcentrald-asic/src/protocol.rs` (+ the BM1362 frame
builders in `dcentrald-asic/src/bm1362/mod.rs` and the response parsers in
`dcentrald-asic/src/bm1362/{assigned_address,uart_transport}.rs`).  This
module is the single source of wire truth for the emu-twin chain emulator;
when this file and the Rust disagree, the Rust wins and this file gets fixed.

Wire formats (see the Rust module docs):

  Command frame (host -> ASIC):
      [0x55] [0xAA] [header] [length] [payload...] [CRC5]
      `length` counts every byte after the preamble (header+length+payload+CRC),
      so 5-byte frames carry length 0x05 and 9-byte register writes 0x09.

  Job frame (host -> ASIC, BM1362/BM1366-class full-header serial dispatch):
      [0x55] [0xAA] [0x21] [len] [82-byte payload] [CRC16 hi] [CRC16 lo]
      Total 88 bytes on the wire.  The proven BM1362 builder writes len=0x56
      (86 = hdr+len+payload+CRC16); the S19k Track-1 bosminer packer writes
      len=0x36 (bosminer's own encoding of the same 88-byte frame).  Both are
      accepted on receive; the frame boundary comes from the fixed payload
      size, and the CRC16 covers bytes [2:86] either way.

  Response frame (ASIC -> host):
      [0xAA] [0x55] [payload] [trailer]
      BM136x: 8-byte payload + 1 trailer byte = 9 body bytes, 11 wire bytes.
      BM1387/BM139x: 6-byte payload + 1 trailer = 7 body bytes, 9 wire bytes.
      (Body-byte/wire-byte constants mirror
      `dcentrald-api-types::asic_protocol_spec`: BM136X_RESPONSE_BODY_BYTES=9,
      BM139X_RESPONSE_BODY_BYTES=7, wire = preamble(2) + body.)
      Trailer bit7 = job-response marker; bits 6:5 = flags (not modeled);
      bits 4:0 = response CRC5.

CRCs:
  CMD packets:   CRC-5, poly 0x05, init 0x1F, MSB-first
                 (port of `dcentrald_common::bm1396_command_crc5`).
  Responses:     modified CRC-5 state machine, init 0x03 for command/register
                 responses (port of `bm13xx_response_crc5_with_init`; verbatim
                 logical equivalent of Braiins `crc5_resp_serial.vhd`).
  JOB packets:   CRC-16 CCITT-FALSE, poly 0x1021, init 0xFFFF, appended
                 big-endian.

Tier honesty: this module is byte-model code (T1 sim surface).  Its vectors
are pinned against retained in-tree oracle fixtures, not live silicon.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Preambles / baud ladder
# ---------------------------------------------------------------------------

CMD_PREAMBLE = bytes([0x55, 0xAA])   # host -> ASIC
RESP_PREAMBLE = bytes([0xAA, 0x55])  # ASIC -> host

DEFAULT_BAUD = 115_200      # protocol.rs DEFAULT_BAUD
OPERATIONAL_BAUD = 3_125_000  # BM1362 post-enumeration mining baud

# The BM1362-class baud ladder used by the serial routes: enumerate at the
# default rate, then switch the chain to the operational rate after the
# FAST_UART_CONFIG / MiscCtrl writes.
BAUD_LADDER = (DEFAULT_BAUD, OPERATIONAL_BAUD)

# ---------------------------------------------------------------------------
# Header byte encoding (protocol.rs)
# ---------------------------------------------------------------------------

TYPE_CMD = 0x40
TYPE_JOB = 0x20
GROUP_ALL = 0x10

CMD_SETADDR = 0x01   # set chip address
CMD_WRITE = 0x01     # write register — same opcode, differentiated by length
CMD_READ = 0x04      # read register
CMD_INACTIVE = 0x05  # chain inactive (enumeration)
CMD_SETCONFIG = 0x08  # write register with hw_addr (BM1387-style)

# Combined header bytes (TYPE_CMD | ...).
HDR_CMD_SETADDR = TYPE_CMD | CMD_SETADDR          # 0x41
HDR_CMD_WRITE = TYPE_CMD | CMD_WRITE              # 0x41
HDR_CMD_READ = TYPE_CMD | CMD_READ                # 0x44
HDR_CMD_SETCONFIG = TYPE_CMD | CMD_SETCONFIG      # 0x48
HDR_CMD_BCAST_WRITE = TYPE_CMD | GROUP_ALL | CMD_WRITE        # 0x51
HDR_CMD_BCAST_READ = TYPE_CMD | GROUP_ALL | CMD_READ          # 0x54
HDR_CMD_BCAST_SETCONFIG = TYPE_CMD | GROUP_ALL | CMD_SETCONFIG  # 0x58
HDR_CMD_BCAST_INACTIVE = TYPE_CMD | GROUP_ALL | CMD_INACTIVE  # 0x55

# BM1397+/BM1362-family header variants actually emitted by the proven serial
# builders (`bm1362/mod.rs`, `bm1396_contract.rs`): bare-encode headers
# without TYPE_CMD, per the BM139x command set (0x40 setaddr, 0x51/0x52
# bcast write/read, 0x53 inactive, 0x41/0x42 single write/read).
HDR_BM139X_SETADDR = 0x40
HDR_BM139X_WRITE_SINGLE = 0x41
HDR_BM139X_READ_SINGLE = 0x42
HDR_BM139X_WRITE_BCAST = 0x51
HDR_BM139X_READ_BCAST = 0x52
HDR_BM139X_INACTIVE_BCAST = 0x53

HDR_JOB_WRITE = TYPE_JOB | CMD_WRITE  # 0x21

# ---------------------------------------------------------------------------
# Response geometry (asic_protocol_spec.rs)
# ---------------------------------------------------------------------------

RESPONSE_PREAMBLE_BYTES = 2
BM1387_RESPONSE_BODY_BYTES = 7
BM139X_RESPONSE_BODY_BYTES = 7
BM136X_RESPONSE_BODY_BYTES = 9

# Wire bytes including the AA 55 preamble.
BM136X_RESPONSE_WIRE_BYTES = RESPONSE_PREAMBLE_BYTES + BM136X_RESPONSE_BODY_BYTES  # 11
BM139X_RESPONSE_WIRE_BYTES = RESPONSE_PREAMBLE_BYTES + BM139X_RESPONSE_BODY_BYTES  # 9

# BM1362 11-byte nonce-response trailer flag bit: bit7 = job-response frame
# (uart_transport.rs Bm1362SerialNonce.flags).
NONCE_FLAGS_JOB_RESPONSE = 0x80

# ---------------------------------------------------------------------------
# BM1362 chip constants (drivers/bm1362.rs, bm1362/assigned_address.rs)
# ---------------------------------------------------------------------------

BM1362_CHIP_ID = 0x1362
BM1362_CORE_COUNT_ENCODING = 0x03
BM1362_RESPONSE_BYTES = 11
BM1362_CHIPS_PER_CHAIN = 126          # S19j Pro BHB42601
BM1362_ADDRESS_INTERVAL = 2           # floor(256/126), bosminer 0x00,0x02,0x04...

JOB_ID_INCREMENT = 24                 # job ids cycle 0,24,48,...,120,16,...
JOB_ID_MASK = 0x7F                    # only bits [7:3] echo usefully

# BM1362 register map (drivers/bm1362.rs `regs`).
REG_CHIP_ADDRESS = 0x00        # bits 31:16 = ChipID
REG_PLL0 = 0x08                # hash clock PLL
REG_HASH_COUNTING_NUMBER = 0x10
REG_TICKET_MASK = 0x14         # hardware difficulty filter
REG_MISC_CONTROL = 0x18        # UART/clock config; triple-write only
REG_FAST_UART_CONFIG = 0x28    # baud rate (S19k stock law 0x00003011)
REG_UART_RELAY = 0x2C
REG_CORE_REG_CTRL = 0x3C
REG_ANALOG_MUX = 0x54          # temperature diode
REG_IO_DRIVER_STRENGTH = 0x58
REG_PLL1 = 0x60                # baud-rate PLL (reclock >= 3_000_001 baud)
REG_PLL3 = 0x68
REG_VERSION_MASK = 0xA4        # BIP320 version-rolling mask
REG_INIT_CONTROL = 0xA8

PLL_LOCK_BIT = 0x8000_0000
BM1362_XIN_HZ = 25_000_000     # PLL reference clock (DECLARED 25 MHz)

# Cold-boot law values (bm1362/mod.rs cold_boot_step).
FAST_UART_CONFIG_VALUE = 0x0000_3011
MISC_CONTROL_VALUE_POST_FAST_BAUD = 0x00C1_00B0

# BIP320 version rolling ( am2 BM1362 load-bearing rule).
VERSION_ROLLING_FIELD_MASK = 0x1FFFE000
VERSION_ROLLING_SHIFT = 13

# ---------------------------------------------------------------------------
# Job-frame geometry (drivers/bm1362.rs build_serial_work_frame)
# ---------------------------------------------------------------------------

JOB_PAYLOAD_BYTES = 82
JOB_FRAME_WIRE_BYTES = 88
JOB_LEN_BYTE_PROVEN = 0x56    # BM1362 builder: 86 = hdr+len+payload+CRC16
JOB_LEN_BYTE_S19K_T1 = 0x36   # S19k Track-1 bosminer encoding (same 88 B frame)
JOB_LEN_ACCEPTED = frozenset({JOB_LEN_BYTE_PROVEN, JOB_LEN_BYTE_S19K_T1})

# ---------------------------------------------------------------------------
# CRC-5 for command packets (poly 0x05, init 0x1F, MSB-first)
# ---------------------------------------------------------------------------


def crc5(data: bytes) -> int:
    """Command CRC-5 — verbatim port of `bm1396_command_crc5`.

    Polynomial x^5 + x^2 + 1 (0x05 feedback), initial state 0x1F, MSB first.
    """
    crc = 0x1F
    for byte in data:
        for bit_index in range(7, -1, -1):
            input_bit = (byte >> bit_index) & 1
            crc_top = (crc >> 4) & 1
            crc = (crc << 1) & 0x1F
            if input_bit ^ crc_top:
                crc ^= 0x05
    return crc


# ---------------------------------------------------------------------------
# BM13xx response CRC-5 (modified transition, init 0x03)
# ---------------------------------------------------------------------------

RESPONSE_CRC5_INIT_COMMAND = 0x03
RESPONSE_CRC5_INIT_JOB = 0x1B  # seven-byte job-body init (protocol.rs; not
# used by the BM136x extended UART nonce frames — those carry full-body
# remainder-zero semantics in the held captures; we pin the trailer via the
# command init for cross-consistency, see README "deviations").


def response_crc5(data: bytes, init: int = RESPONSE_CRC5_INIT_COMMAND) -> int:
    """BM13xx command/register response CRC-5 — verbatim port of
    `bm13xx_response_crc5_with_init` (Braiins `crc5_resp_serial.vhd`).

    `data` is the response payload only (no AA 55 preamble, no trailer byte).
    """
    crc = init & 0x1F
    for byte in data:
        for bit_index in range(7, -1, -1):
            data_bit = (byte >> bit_index) & 1
            feedback = data_bit ^ ((crc >> 4) & 1)
            # Logical equivalent of crc5_resp_serial.vhd: universal shift
            # c[4:0] <- c[3:0] & feedback, c2 <- old_c1^feedback,
            # c3 <- old_c2 ^ data_bit (non-standard update).
            crc = (
                (((crc >> 3) & 1) << 4)
                | ((((crc >> 2) & 1) ^ data_bit) << 3)
                | ((((crc >> 1) & 1) ^ feedback) << 2)
                | ((crc & 1) << 1)
                | feedback
            )
    return crc


# ---------------------------------------------------------------------------
# CRC-16 CCITT-FALSE for job packets (poly 0x1021, init 0xFFFF)
# ---------------------------------------------------------------------------


def crc16(data: bytes) -> int:
    """Job CRC-16 CCITT-FALSE — verbatim port of `protocol::crc16`.

    Result is appended big-endian (MSB first) by the frame builders.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Command frame builders (mirror of bm1362/mod.rs builders)
# ---------------------------------------------------------------------------


def _cmd_frame(body_without_crc: bytes) -> bytes:
    return CMD_PREAMBLE + body_without_crc + bytes([crc5(body_without_crc)])


def chain_inactive_frame() -> bytes:
    """ChainInactive broadcast: `[55 AA] 53 05 00 00 CRC5` (BM1362 law)."""
    return _cmd_frame(bytes([HDR_BM139X_INACTIVE_BCAST, 0x05, 0x00, 0x00]))


def chain_inactive_frame_bm1387() -> bytes:
    """BM1387 variant: header 0x55 (protocol.rs FIFO_CMD_CHAIN_INACTIVE)."""
    return _cmd_frame(bytes([HDR_CMD_BCAST_INACTIVE, 0x05, 0x00, 0x00]))


def get_address_frame() -> bytes:
    """GetAddress broadcast read of reg 0x00: `[55 AA] 52 05 00 00 CRC5`."""
    return _cmd_frame(bytes([HDR_BM139X_READ_BCAST, 0x05, 0x00, REG_CHIP_ADDRESS]))


def get_address_frame_bm1387() -> bytes:
    """BM1387 variant: header 0x54 (protocol.rs FIFO_CMD_GET_ADDRESS)."""
    return _cmd_frame(bytes([HDR_CMD_BCAST_READ, 0x05, 0x00, REG_CHIP_ADDRESS]))


def set_chip_address_frame(addr: int) -> bytes:
    """SetChipAddress: `[55 AA] 40 05 ADDR 00 CRC5`."""
    return _cmd_frame(bytes([HDR_BM139X_SETADDR, 0x05, addr & 0xFF, 0x00]))


def broadcast_write_frame(reg: int, value: int) -> bytes:
    """Broadcast register write: `[55 AA] 51 09 00 REG VAL_BE[4] CRC5`."""
    return _cmd_frame(
        bytes([HDR_BM139X_WRITE_BCAST, 0x09, 0x00, reg])
        + struct.pack(">I", value & 0xFFFFFFFF)
    )


def single_write_frame(chip_addr: int, reg: int, value: int) -> bytes:
    """Per-chip register write: `[55 AA] 41 09 CHIP REG VAL_BE[4] CRC5`."""
    return _cmd_frame(
        bytes([HDR_BM139X_WRITE_SINGLE, 0x09, chip_addr & 0xFF, reg])
        + struct.pack(">I", value & 0xFFFFFFFF)
    )


def single_read_frame(chip_addr: int, reg: int) -> bytes:
    """Per-chip register read: `[55 AA] 42 05 CHIP REG CRC5`
    (mirror of `bm1396_read_register_frame` non-broadcast form)."""
    return _cmd_frame(
        bytes([HDR_BM139X_READ_SINGLE, 0x05, chip_addr & 0xFF, reg])
    )


# ---------------------------------------------------------------------------
# Command frame parsing
# ---------------------------------------------------------------------------


@dataclass
class CmdFrame:
    """One decoded host->ASIC command frame."""

    header: int
    opcode: int            # header & 0x0F (low nibble opcode space)
    broadcast: bool        # GROUP_ALL set
    is_job: bool           # TYPE_JOB set
    chip_addr: int         # payload byte 0 (0 for broadcast)
    reg: int               # payload byte 1 (register space)
    value: Optional[int]   # 4-byte BE value for 9-byte writes, else None
    raw: bytes = field(repr=False, default=b"")

    @property
    def is_setaddr(self) -> bool:
        """SETADDR vs WRITE is differentiated by frame length (5 vs 9).

        Covers both header spaces: TYPE_CMD|SETADDR (0x41, BM1387-style) and
        the bare BM139x-family setaddr header (0x40).
        """
        if self.value is not None:
            return False  # 9-byte frame = register write
        return self.opcode == CMD_SETADDR or self.header == HDR_BM139X_SETADDR


class ProtocolError(ValueError):
    """Raised on malformed/unverifiable frames."""


def parse_cmd_frame(buf: bytes) -> CmdFrame:
    """Parse one complete command frame (buf = exactly one frame, preamble
    included).  Raises ProtocolError on bad preamble/CRC/length."""
    if len(buf) < 5 or buf[:2] != CMD_PREAMBLE:
        raise ProtocolError(f"bad command preamble: {buf[:2]!r}")
    header = buf[2]
    length = buf[3]
    body = buf[2:-1]
    crc_byte = buf[-1]
    if length != len(buf) - 2 and not (header & TYPE_JOB):
        raise ProtocolError(
            f"length byte {length:#04x} != frame body size {len(buf) - 2}"
        )
    if crc5(body) != crc_byte:
        raise ProtocolError(
            f"CRC5 mismatch: computed {crc5(body):#04x}, wire {crc_byte:#04x}"
        )
    opcode = header & 0x0F
    broadcast = bool(header & GROUP_ALL)
    is_job = bool(header & TYPE_JOB)
    chip_addr = body[2]
    reg = body[3]
    value = struct.unpack(">I", body[4:8])[0] if len(body) == 8 else None
    return CmdFrame(
        header=header,
        opcode=opcode,
        broadcast=broadcast,
        is_job=is_job,
        chip_addr=chip_addr,
        reg=reg,
        value=value,
        raw=bytes(buf),
    )


def expected_cmd_frame_size(header: int, length: int) -> Optional[int]:
    """Total wire size (incl. preamble) a command frame claims, or None.

    JOB frames are NOT length-byte driven (the two proven encodings disagree:
    0x56 BM1362 builder vs 0x36 S19k Track-1) — callers must use the fixed
    88-byte job size from `frame_size_hint` instead.
    """
    if header & TYPE_JOB:
        return None
    if length not in (5, 9):
        return None
    return 2 + length


def frame_size_hint(buf: bytes) -> Optional[int]:
    """Given a receive buffer starting at a 55 AA preamble, return the total
    frame size to consume, or None if not yet decidable."""
    if len(buf) < 4 or buf[:2] != CMD_PREAMBLE:
        return None
    header, length = buf[2], buf[3]
    if header & TYPE_JOB:
        return JOB_FRAME_WIRE_BYTES
    size = expected_cmd_frame_size(header, length)
    return size


# ---------------------------------------------------------------------------
# Job frame build/parse (88-byte BM1362/BM1366 full-header form)
# ---------------------------------------------------------------------------


def _reverse_32bit_words(data: bytes) -> bytes:
    """Reverse 32-bit word order in a 32-byte array (involution).

    Mirror of `drivers/bm1362.rs reverse_32bit_words` — BM1362 expects
    merkle_root and prev_block_hash with each 32-bit word reversed relative
    to internal Bitcoin byte order (the ASIC fixed-function SHA convention).
    """
    if len(data) != 32:
        raise ProtocolError("word reversal needs exactly 32 bytes")
    out = bytearray(32)
    for i in range(8):
        out[i * 4 : i * 4 + 4] = data[(7 - i) * 4 : (7 - i) * 4 + 4]
    return bytes(out)


@dataclass
class JobFields:
    """The full 80-byte Bitcoin header material carried by a job frame."""

    job_id: int
    num_midstates: int
    starting_nonce: int
    nbits: int           # LE on the wire
    ntime: int           # LE on the wire
    merkle_root: bytes   # 32 B, internal byte order (un-reversed)
    prev_block_hash: bytes  # 32 B, internal byte order (un-reversed)
    version: int         # LE on the wire

    def __post_init__(self) -> None:
        if len(self.merkle_root) != 32 or len(self.prev_block_hash) != 32:
            raise ProtocolError("merkle_root/prev_block_hash must be 32 bytes")

    def header_prefix(self, version_bits: int = 0) -> bytes:
        """First 76 header bytes (everything but the nonce), internal order.

        `version_bits` are raw BIP320 vbits: rolled version =
        (base & ~mask) | ((vbits << 13) & mask), mask 0x1FFFE000.
        """
        version = self.version
        if version_bits:
            version = (
                (version & ~VERSION_ROLLING_FIELD_MASK)
                | ((version_bits << VERSION_ROLLING_SHIFT)
                   & VERSION_ROLLING_FIELD_MASK)
            )
        return (
            struct.pack("<I", version)
            + self.prev_block_hash
            + self.merkle_root
            + struct.pack("<II", self.ntime, self.nbits)
        )


def build_job_frame(fields: JobFields) -> bytes:
    """Build the 88-byte BM1362 serial-work wire frame.

    Mirror of `drivers/bm1362.rs build_serial_work_frame`:
    `[55 AA][21][56][82-byte payload][CRC16 BE over bytes 2:86]`.
    """
    payload = bytearray(JOB_PAYLOAD_BYTES)
    payload[0] = fields.job_id & 0xFF
    payload[1] = 0x01  # num_midstates — BM1362 computes its own
    payload[2:6] = struct.pack("<I", fields.starting_nonce & 0xFFFFFFFF)
    payload[6:10] = struct.pack("<I", fields.nbits & 0xFFFFFFFF)
    payload[10:14] = struct.pack("<I", fields.ntime & 0xFFFFFFFF)
    payload[14:46] = _reverse_32bit_words(fields.merkle_root)
    payload[46:78] = _reverse_32bit_words(fields.prev_block_hash)
    payload[78:82] = struct.pack("<I", fields.version & 0xFFFFFFFF)

    frame = bytearray(JOB_FRAME_WIRE_BYTES)
    frame[0:2] = CMD_PREAMBLE
    frame[2] = HDR_JOB_WRITE
    frame[3] = JOB_LEN_BYTE_PROVEN
    frame[4:86] = payload
    csum = crc16(bytes(frame[2:86]))
    frame[86] = (csum >> 8) & 0xFF
    frame[87] = csum & 0xFF
    return bytes(frame)


def parse_job_frame(buf: bytes) -> JobFields:
    """Parse an 88-byte job frame back into header material.

    Accepts both proven length-byte encodings (0x56 and 0x36); the payload
    boundary is fixed at 82 bytes and the CRC16 must cover bytes [2:86].
    """
    if len(buf) != JOB_FRAME_WIRE_BYTES:
        raise ProtocolError(f"job frame must be {JOB_FRAME_WIRE_BYTES} bytes")
    if buf[:2] != CMD_PREAMBLE:
        raise ProtocolError("bad job preamble")
    if buf[2] != HDR_JOB_WRITE:
        raise ProtocolError(f"bad job header byte {buf[2]:#04x}")
    if buf[3] not in JOB_LEN_ACCEPTED:
        raise ProtocolError(f"unproven job length byte {buf[3]:#04x}")
    wire_crc = (buf[86] << 8) | buf[87]
    computed = crc16(buf[2:86])
    if wire_crc != computed:
        raise ProtocolError(
            f"job CRC16 mismatch: computed {computed:#06x}, wire {wire_crc:#06x}"
        )
    payload = buf[4:86]
    return JobFields(
        job_id=payload[0],
        num_midstates=payload[1],
        starting_nonce=struct.unpack("<I", payload[2:6])[0],
        nbits=struct.unpack("<I", payload[6:10])[0],
        ntime=struct.unpack("<I", payload[10:14])[0],
        merkle_root=_reverse_32bit_words(payload[14:46]),
        prev_block_hash=_reverse_32bit_words(payload[46:78]),
        version=struct.unpack("<I", payload[78:82])[0],
    )


# ---------------------------------------------------------------------------
# Response builders (ASIC -> host)
# ---------------------------------------------------------------------------


def build_register_response(
    chip_addr: int,
    reg: int,
    value: int,
    chip_id: int = BM1362_CHIP_ID,
    core_count_encoding: int = BM1362_CORE_COUNT_ENCODING,
) -> bytes:
    """Build the 11-byte BM136x register/command response frame.

    Layout pinned by `bm1362/assigned_address.rs
    parse_assigned_address_response` (reg 0x00):
      [AA 55][value BE(4)][responder_addr(1)][reg(1)][rsvd 00 00][trailer]
    where for CHIP_ADDRESS the value packs chip_id(31:16), core-count
    encoding (15:8), address (7:0).  The trailer carries
    response_crc5(payload) in bits 4:0 with bit7 clear (command response).
    """
    if reg == REG_CHIP_ADDRESS:
        value = (
            ((chip_id & 0xFFFF) << 16)
            | ((core_count_encoding & 0xFF) << 8)
            | (chip_addr & 0xFF)
        )
    payload = (
        struct.pack(">I", value & 0xFFFFFFFF)
        + bytes([chip_addr & 0xFF, reg & 0xFF, 0x00, 0x00])
    )
    trailer = response_crc5(payload) & 0x1F  # bit7 clear: command response
    return RESP_PREAMBLE + payload + bytes([trailer])


def build_nonce_response(
    nonce: int,
    job_id: int,
    version_bits: int = 0,
    midstate_idx: int = 0,
    small_core: int = 0,
) -> bytes:
    """Build the 11-byte BM1362 serial nonce frame.

    Layout per `am3_bb_mining.rs` module doc + `uart_transport.rs
    parse_bm1362_serial_nonce`:
      [AA 55][nonce LE(4)][midstate_idx][result][vbits BE(2)][flags]
    result = job_id bits [6:3] in the high nibble | small core in the low
    nibble; flags = 0x80 (job-response) | response_crc5(payload) in 4:0.
    """
    result = (((job_id >> 3) & 0x0F) << 4) | (small_core & 0x0F)
    payload = (
        struct.pack("<I", nonce & 0xFFFFFFFF)
        + bytes([midstate_idx & 0xFF, result & 0xFF])
        + struct.pack(">H", version_bits & 0xFFFF)
    )
    flags = NONCE_FLAGS_JOB_RESPONSE | (response_crc5(payload) & 0x1F)
    return RESP_PREAMBLE + payload + bytes([flags])


@dataclass
class NonceResponse:
    """Parsed 11-byte nonce response (mirror of Bm1362SerialNonce)."""

    nonce: int
    job_id: int               # (result & 0xF0) >> 1 — bits [6:3] of sent id
    result_byte: int
    small_core: int
    midstate_idx: int
    version_bits_raw: int     # BE; rolled version = (base&~mask)|((vbits<<13)&mask)
    flags: int                # bit7 = job-response, bits 4:0 = CRC5

    @property
    def is_job_response(self) -> bool:
        return bool(self.flags & NONCE_FLAGS_JOB_RESPONSE)

    def rolled_version(self, base_version: int) -> int:
        return (
            (base_version & ~VERSION_ROLLING_FIELD_MASK)
            | ((self.version_bits_raw << VERSION_ROLLING_SHIFT)
               & VERSION_ROLLING_FIELD_MASK)
        )


def parse_nonce_response(buf: bytes) -> NonceResponse:
    """Parse an 11-byte BM1362 serial nonce frame.

    Validates preamble and length only — the proven daemon path does not
    validate the trailer CRC5 either (TicketMask gates which nonces return).
    """
    if len(buf) < BM136X_RESPONSE_WIRE_BYTES:
        raise ProtocolError("nonce frame too short")
    if buf[:2] != RESP_PREAMBLE:
        raise ProtocolError("bad response preamble")
    b = buf[2:11]
    id_byte = b[5]
    return NonceResponse(
        nonce=struct.unpack("<I", b[0:4])[0],
        job_id=(id_byte & 0xF0) >> 1,
        result_byte=id_byte,
        small_core=id_byte & 0x0F,
        midstate_idx=b[4],
        version_bits_raw=struct.unpack(">H", b[6:8])[0],
        flags=b[8],
    )


@dataclass
class RegisterResponse:
    """Parsed 11-byte register response (mirror of AssignedAddressObservation)."""

    chip_id: int
    core_count_encoding: int
    register_value: int       # BE bytes 2:6 (chip_id<<16 | cc<<8 | addr for reg 0)
    responder_address: int
    reg: int
    trailer: int
    expected_crc5: int        # recomputed value the parser verified


def parse_register_response(buf: bytes) -> RegisterResponse:
    """Parse + CRC-verify an 11-byte BM136x register response.

    Enforces the same admission law as `parse_assigned_address_response`:
    trailer bit7 clear (command response), bits 6:5 clear, CRC5 over the
    8-byte payload.
    """
    if len(buf) != BM136X_RESPONSE_WIRE_BYTES:
        raise ProtocolError(f"register response must be 11 bytes, got {len(buf)}")
    if buf[:2] != RESP_PREAMBLE:
        raise ProtocolError("bad response preamble")
    trailer = buf[10]
    if trailer & NONCE_FLAGS_JOB_RESPONSE:
        raise ProtocolError("job-response trailer on register frame")
    if trailer & 0x60:
        raise ProtocolError(f"unsupported trailer flags {trailer:#04x}")
    payload = buf[2:10]
    expected = response_crc5(payload)
    if (trailer & 0x1F) != expected:
        raise ProtocolError(
            f"response CRC5 mismatch: computed {expected:#04x}, "
            f"wire {trailer & 0x1F:#04x}"
        )
    return RegisterResponse(
        chip_id=struct.unpack(">H", payload[0:2])[0],
        core_count_encoding=payload[2],
        register_value=struct.unpack(">I", payload[0:4])[0],
        responder_address=payload[4],
        reg=payload[5],
        trailer=trailer,
        expected_crc5=expected,
    )


# ---------------------------------------------------------------------------
# PLL decode (drivers/bm1362.rs decode_pll_reg_to_freq)
# ---------------------------------------------------------------------------


def decode_pll_reg_to_freq_mhz(raw_reg: int) -> Optional[int]:
    """Decode a BM1362 PLL reg-0x08 value to MHz.

    freq = 25*FBDIV / (REFDIV * POSTDIV1 * POSTDIV2), ignoring the lock bit
    and VCO_SCALE band byte.
    """
    reg = raw_reg & ~PLL_LOCK_BIT
    fbdiv = (reg >> 16) & 0xFF
    refdiv = max((reg >> 8) & 0xFF, 1)
    postdiv = reg & 0xFF
    pd1 = ((postdiv >> 4) & 0x0F) + 1
    pd2 = (postdiv & 0x0F) + 1
    denom = refdiv * pd1 * pd2
    if denom == 0 or fbdiv == 0:
        return None
    freq_hz = BM1362_XIN_HZ * fbdiv // denom
    if freq_hz <= 0 or freq_hz > 10_000_000_000:
        return None
    return round(freq_hz / 1_000_000)


__all__ = [
    "CMD_PREAMBLE",
    "RESP_PREAMBLE",
    "DEFAULT_BAUD",
    "OPERATIONAL_BAUD",
    "BAUD_LADDER",
    "TYPE_CMD",
    "TYPE_JOB",
    "GROUP_ALL",
    "CMD_SETADDR",
    "CMD_WRITE",
    "CMD_READ",
    "CMD_INACTIVE",
    "CMD_SETCONFIG",
    "HDR_CMD_SETADDR",
    "HDR_CMD_WRITE",
    "HDR_CMD_READ",
    "HDR_CMD_SETCONFIG",
    "HDR_CMD_BCAST_WRITE",
    "HDR_CMD_BCAST_READ",
    "HDR_CMD_BCAST_SETCONFIG",
    "HDR_CMD_BCAST_INACTIVE",
    "HDR_BM139X_SETADDR",
    "HDR_BM139X_WRITE_SINGLE",
    "HDR_BM139X_READ_SINGLE",
    "HDR_BM139X_WRITE_BCAST",
    "HDR_BM139X_READ_BCAST",
    "HDR_BM139X_INACTIVE_BCAST",
    "HDR_JOB_WRITE",
    "RESPONSE_PREAMBLE_BYTES",
    "BM1387_RESPONSE_BODY_BYTES",
    "BM139X_RESPONSE_BODY_BYTES",
    "BM136X_RESPONSE_BODY_BYTES",
    "BM136X_RESPONSE_WIRE_BYTES",
    "BM139X_RESPONSE_WIRE_BYTES",
    "NONCE_FLAGS_JOB_RESPONSE",
    "BM1362_CHIP_ID",
    "BM1362_CORE_COUNT_ENCODING",
    "BM1362_RESPONSE_BYTES",
    "BM1362_CHIPS_PER_CHAIN",
    "BM1362_ADDRESS_INTERVAL",
    "JOB_ID_INCREMENT",
    "JOB_ID_MASK",
    "REG_CHIP_ADDRESS",
    "REG_PLL0",
    "REG_HASH_COUNTING_NUMBER",
    "REG_TICKET_MASK",
    "REG_MISC_CONTROL",
    "REG_FAST_UART_CONFIG",
    "REG_UART_RELAY",
    "REG_CORE_REG_CTRL",
    "REG_ANALOG_MUX",
    "REG_IO_DRIVER_STRENGTH",
    "REG_PLL1",
    "REG_PLL3",
    "REG_VERSION_MASK",
    "REG_INIT_CONTROL",
    "PLL_LOCK_BIT",
    "BM1362_XIN_HZ",
    "FAST_UART_CONFIG_VALUE",
    "MISC_CONTROL_VALUE_POST_FAST_BAUD",
    "VERSION_ROLLING_FIELD_MASK",
    "VERSION_ROLLING_SHIFT",
    "JOB_PAYLOAD_BYTES",
    "JOB_FRAME_WIRE_BYTES",
    "JOB_LEN_BYTE_PROVEN",
    "JOB_LEN_BYTE_S19K_T1",
    "crc5",
    "response_crc5",
    "RESPONSE_CRC5_INIT_COMMAND",
    "RESPONSE_CRC5_INIT_JOB",
    "crc16",
    "chain_inactive_frame",
    "chain_inactive_frame_bm1387",
    "get_address_frame",
    "get_address_frame_bm1387",
    "set_chip_address_frame",
    "broadcast_write_frame",
    "single_write_frame",
    "single_read_frame",
    "parse_cmd_frame",
    "expected_cmd_frame_size",
    "frame_size_hint",
    "JobFields",
    "build_job_frame",
    "parse_job_frame",
    "build_register_response",
    "build_nonce_response",
    "parse_nonce_response",
    "parse_register_response",
    "NonceResponse",
    "RegisterResponse",
    "decode_pll_reg_to_freq_mhz",
    "ProtocolError",
]
