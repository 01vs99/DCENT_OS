"""Host-side I2C device-emulation sidecar service for the DCENT_OS emu-twin.

Implements the *semantics* of the peripherals ``dcentrald`` actually talks to
on a real control board, behind a documented TCP JSON-line contract
(``sidecar_protocol.md``). This is deliberately NOT a raw I2C wire: per
campaign fold C1-F1, the guest-attachment mechanism for I2C (how a QEMU guest
``/dev/i2c-N`` reaches this service) is an OPEN PoC — Linux ``i2c-stub``
cannot carry the daemon's raw ``I2C_RDWR`` ioctls (EOPNOTSUPP), and virtio-i2c
is absent from the held 4.4 kernels. The sidecar models devices; a future
guest agent would translate.

Device semantics mirror the HAL sources:

* PMBus PSU telemetry (``dcentrald-hal/src/pmbus.rs``): command codes
  VOUT_MODE 0x20, READ_VIN 0x88, READ_IIN 0x89, READ_VOUT 0x8B, READ_IOUT
  0x8C, READ_TEMPERATURE_1 0x8D, READ_FAN_SPEED_1 0x90, READ_POUT 0x96,
  READ_PIN 0x97, STATUS_WORD 0x79, MFR_ID/MFR_MODEL/MFR_REVISION blocks;
  SLINEAR11 (signed 11-bit mantissa + signed 5-bit exponent) and ULINEAR16
  (VOUT_MODE exponent) encodings; address 0x58 (alt 0x59).
* PMBus OPERATION (0x01): the production pmbus.rs layer is read-only
  telemetry, so the sidecar carries the standard PMBus on/off byte
  (0x80 = on, 0x00 = off) for completeness of PMBus-class semantics.
* APW12 SMBus PSU (``dcentrald-hal/src/psu_apw12_smbus.rs``): address 0x10,
  17 opcodes (POWER_OFF 0x00 .. GET_POWER_SN 0x10), FW version 0x0103,
  SET_VOLTAGE payload = millivolts LE, READ_TELEMETRY block = 32 bytes,
  VOLTAGE_MAX_MV = 1600.
* EMC2305-class fan controller: PWM duty per fan (0x40..0x44), tach telemetry
  honoring **2 pulses/rev** (``dcentrald-hal/src/platform/amlogic/mod.rs``
  PULSES_PER_REV). CLASS-level model, not a bit-exact EMC2305 register map.
* LM75/TMP75 temperature sensors (``dcentrald-hal/src/i2c.rs``): 0x48..0x4F,
  temp register 0x00 = signed 16-bit big-endian in 1/256 degC units.
* AT24-class EEPROMs at 0x50..0x57: **all writes REFUSED** — this is the G1
  EEPROM write-denylist semantics. The twin TESTS the invariant, never
  bypasses it: the sidecar counts every refused write in ``stats`` under
  ``eeprom_write_denied``.
* dsPIC framed ops (presence stub): 0x20..0x22, frames ``55 AA 17``
  (GET_VERSION), ``55 AA 04 15 01`` (ENABLE), ``55 AA 04 16 00`` (HEARTBEAT);
  fw byte selectable (0x89 S19j admission, 0x86 degraded → daemon G2 refusal
  path).

Fault injectors (default OFF; feed the tuner fault-injection suite):
``readback_lag`` (values served lag physics truth by N seconds),
``readback_lie`` (scale/offset applied to selected quantities),
``stuck_value`` (reads frozen at arm time).

Standard-library only (Python 3.9+), localhost only. CLI::

    py -3 i2c_sidecar.py --port 17003
"""

from __future__ import annotations

import argparse
import json
import socketserver
import struct
import sys
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# Register/command constants (mirrored from the HAL sources named above)
# ---------------------------------------------------------------------------

PMBUS_ADDR = 0x58
PMBUS_ADDR_ALT = 0x59
PMBUS_OPERATION = 0x01
PMBUS_VOUT_MODE = 0x20
PMBUS_STATUS_WORD = 0x79
PMBUS_READ_VIN = 0x88
PMBUS_READ_IIN = 0x89
PMBUS_READ_VOUT = 0x8B
PMBUS_READ_IOUT = 0x8C
PMBUS_READ_TEMPERATURE_1 = 0x8D
PMBUS_READ_FAN_SPEED_1 = 0x90
PMBUS_READ_POUT = 0x96
PMBUS_READ_PIN = 0x97
PMBUS_MFR_ID = 0x99
PMBUS_MFR_MODEL = 0x9A
PMBUS_MFR_REVISION = 0x9B

APW12_ADDR = 0x10
APW12_FW_VERSION = 0x0103
APW12_TELEMETRY_BLOCK_LEN = 32
APW12_VOLTAGE_MAX_MV = 1600

LM75_FIRST_ADDR = 0x48
LM75_LAST_ADDR = 0x4F

EEPROM_FIRST_ADDR = 0x50
EEPROM_LAST_ADDR = 0x57
EEPROM_PAGE_LEN = 256
EEPROM_IDENTITY_PREFIX_LEN = 32

EMC2305_CLASS_ADDR = 0x2F
EMC2305_CLASS_FANS = 5
EMC2305_PWM_BASE_REG = 0x40
EMC2305_TACH_BASE_REG = 0x30  # collision-free class map: tach 0x30..0x38, PWM 0x40..0x44
PULSES_PER_REV = 2  # amlogic/mod.rs PULSES_PER_REV

DSPIC_ADDRS = (0x20, 0x21, 0x22)
DSPIC_GET_VERSION = bytes([0x55, 0xAA, 0x17])
DSPIC_ENABLE = bytes([0x55, 0xAA, 0x04, 0x15, 0x01])
DSPIC_HEARTBEAT = bytes([0x55, 0xAA, 0x04, 0x16, 0x00])
DSPIC_FW_DEFAULT = 0x89
DSPIC_FW_DEGRADED = 0x86  # daemon must refuse this (G2) — twin TESTS it


class SidecarError(Exception):
    """Protocol-level failure carrying a machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# PMBus numeric formats (pmbus.rs SLINEAR11 / ULINEAR16)
# ---------------------------------------------------------------------------


def extend_pmbus_exponent(raw_5bit: int) -> int:
    """Sign-extend a PMBus 5-bit two's-complement exponent (-16..=15)."""
    masked = raw_5bit & 0x1F
    if masked & 0x10:
        return masked - 32
    return masked


def slinear11_encode(value: float) -> int:
    """Encode a float into a PMBus SLINEAR11 16-bit word.

    Iterates the exponent from -16 upward and returns the FIRST encoding
    whose mantissa fits signed 11 bits — i.e. the smallest representable
    exponent, which is the highest-precision encoding. Non-dyadic values
    quantize to the mantissa step (standard PMBus behavior), so
    encode/decode round-trips within one mantissa half-step.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise SidecarError("bad-request", "cannot encode non-finite PMBus value")
    if value == 0:
        return 0
    for exp in range(-16, 16):
        mantissa = int(round(value * (2.0 ** -exp)))
        if -1024 <= mantissa <= 1023:
            return ((exp & 0x1F) << 11) | (mantissa & 0x7FF)
    raise SidecarError("bad-request", f"SLINEAR11 range exceeded: {value!r}")


def slinear11_decode(word: int) -> float:
    """Decode a PMBus SLINEAR11 16-bit word."""
    exp = extend_pmbus_exponent((word >> 11) & 0x1F)
    mantissa = word & 0x07FF
    if mantissa >= 0x400:  # signed 11-bit
        mantissa -= 0x800
    return mantissa * (2.0 ** exp)


def ulinear16_encode(value: float, exponent: int) -> int:
    raw = int(round(value / (2.0 ** exponent)))
    if not 0 <= raw <= 0xFFFF:
        raise SidecarError("bad-request", f"ULINEAR16 range exceeded: {value!r}")
    return raw


def ulinear16_decode(raw: int, exponent: int) -> float:
    return raw * (2.0 ** exponent)


def lm75_temp_encode(temp_c: float) -> int:
    """LM75 temp register: signed 16-bit big-endian, 1/256 degC units."""
    raw = int(round(temp_c * 256.0))
    if not -32768 <= raw <= 32767:
        raise SidecarError("bad-request", f"LM75 range exceeded: {temp_c!r}")
    return raw & 0xFFFF


def lm75_temp_decode(raw_be: int) -> float:
    value = raw_be if raw_be < 0x8000 else raw_be - 0x10000
    return value / 256.0


# ---------------------------------------------------------------------------
# Fault injectors
# ---------------------------------------------------------------------------


class FaultInjector:
    """Base class; ``apply`` maps (quantity, current_value) -> served_value."""

    def __init__(self, kind: str, params: Optional[Dict[str, object]] = None) -> None:
        self.kind = kind
        self.params = dict(params or {})
        self.armed_at = time.time()

    def apply(self, device: "EmuDevice", quantity: str, value: float, now: float) -> float:
        raise NotImplementedError


class ReadbackLagInjector(FaultInjector):
    """Serve the value the physics model held N seconds ago."""

    def __init__(self, params: Optional[Dict[str, object]] = None) -> None:
        super().__init__("readback_lag", params)
        self.seconds = float(self.params.get("seconds", 1.0))

    def apply(self, device: "EmuDevice", quantity: str, value: float, now: float) -> float:
        cutoff = now - self.seconds
        chosen: Optional[Dict[str, float]] = None
        for ts, _seq, snapshot in device.history:
            if ts <= cutoff:
                chosen = snapshot
            else:
                break
        if chosen is None:
            chosen = device.history[0][2] if device.history else {}
        return chosen.get(quantity, value)


class ReadbackLieInjector(FaultInjector):
    """Serve scaled/offset values (e.g. a PSU reporting 10% high)."""

    def __init__(self, params: Optional[Dict[str, object]] = None) -> None:
        super().__init__("readback_lie", params)
        self.scale = float(self.params.get("scale", 1.0))
        self.offset = float(self.params.get("offset", 0.0))
        quantities = self.params.get("quantities")
        self.quantities: Optional[List[str]] = (
            [str(q) for q in quantities] if quantities is not None else None
        )

    def apply(self, device: "EmuDevice", quantity: str, value: float, now: float) -> float:
        if self.quantities is not None and quantity not in self.quantities:
            return value
        return value * self.scale + self.offset


class StuckValueInjector(FaultInjector):
    """Freeze every read at the values present when the injector armed."""

    def __init__(self, params: Optional[Dict[str, object]] = None) -> None:
        super().__init__("stuck_value", params)

    def apply(self, device: "EmuDevice", quantity: str, value: float, now: float) -> float:
        # Ordered by device sequence number, NOT wall clock: fast test
        # sequences can land multiple snapshots on the same tick.
        armed_seq = int(getattr(self, "armed_seq", 0))
        chosen: Optional[Dict[str, float]] = None
        for _ts, seq, snapshot in device.history:
            if seq <= armed_seq:
                chosen = snapshot
            else:
                break
        if chosen is None:
            chosen = device.history[0][2] if device.history else {}
        return chosen.get(quantity, value)


INJECTOR_KINDS = {
    "readback_lag": ReadbackLagInjector,
    "readback_lie": ReadbackLieInjector,
    "stuck_value": StuckValueInjector,
}


# ---------------------------------------------------------------------------
# Device model base
# ---------------------------------------------------------------------------


class EmuDevice:
    """Common machinery: physics-truth values, history, fault injectors."""

    kind = "abstract"

    def __init__(self, name: str, addresses: Sequence[int]) -> None:
        self.name = name
        self.addresses = list(addresses)
        self._truth: Dict[str, float] = {}
        # history entries: (wall ts, device sequence, frozen snapshot); the
        # sequence number gives a total order even when clock ticks collide.
        self.history: List[Tuple[float, int, Dict[str, float]]] = []
        self._seq = 0
        self._injectors: List[FaultInjector] = []
        self.reads = 0
        self.writes = 0
        self.denied = 0

    # -- physics model input (host twin pushes truth) ------------------------
    def set_values(self, values: Dict[str, float]) -> None:
        self._truth.update({k: float(v) for k, v in values.items()})
        self._snapshot()

    def _snapshot(self) -> None:
        if not self._truth:
            return  # never record an empty pre-seed state
        self._seq += 1
        self.history.append((time.time(), self._seq, dict(self._truth)))
        if len(self.history) > 4096:
            del self.history[:2048]

    def truth(self, quantity: str, default: float = 0.0) -> float:
        """Raw physics truth (no injectors) — for tests/diagnostics."""
        return float(self._truth.get(quantity, default))

    def served(self, quantity: str, default: float = 0.0) -> float:
        """Value a guest read would observe (injector chain applied)."""
        now = time.time()
        value = self._truth.get(quantity, default)
        for injector in self._injectors:
            value = injector.apply(self, quantity, value, now)
        return value

    # -- injectors ------------------------------------------------------------
    def inject(self, kind: str, params: Optional[Dict[str, object]] = None) -> None:
        cls = INJECTOR_KINDS.get(kind)
        if cls is None:
            raise SidecarError("bad-request", f"unknown injector kind {kind!r}")
        injector = cls(params)
        if isinstance(injector, StuckValueInjector):
            # ensure history covers the arm point
            self._snapshot()
            injector.armed_seq = self._seq  # type: ignore[attr-defined]
        injector.armed_at = time.time()
        self._injectors.append(injector)

    def clear_injectors(self) -> None:
        self._injectors.clear()

    def injector_state(self) -> List[Dict[str, object]]:
        return [{"kind": i.kind, "params": i.params, "armed_at": i.armed_at} for i in self._injectors]

    # -- bus interface (SMBus-shaped; subclasses implement) -------------------
    def read_command(self, reg: int, read_len: int) -> bytes:
        """Write ``reg`` (command/pointer), repeated START, read ``read_len``."""
        raise SidecarError("unsupported", f"{self.kind} does not implement reads")

    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        raise SidecarError("unsupported", f"{self.kind} does not implement writes")

    def raw_exchange(self, tx: bytes) -> bytes:
        raise SidecarError("unsupported", f"{self.kind} has no raw framed interface")

    def describe(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "addresses": [f"0x{a:02X}" for a in self.addresses],
            "reads": self.reads,
            "writes": self.writes,
            "denied": self.denied,
            "injectors": self.injector_state(),
            "values": dict(self._truth),
        }


# ---------------------------------------------------------------------------
# PMBus PSU (0x58/0x59)
# ---------------------------------------------------------------------------


class PmbusPsu(EmuDevice):
    kind = "pmbus-psu"

    def __init__(
        self,
        name: str = "psu",
        address: int = PMBUS_ADDR,
        vout_mode_exponent: int = -9,
    ) -> None:
        super().__init__(name, [address])
        self.vout_mode_exponent = vout_mode_exponent
        self.operation_byte = 0x80  # on
        self._truth.update(
            vin_v=230.0,
            iin_a=7.2,
            vout_v=13.2,
            iout_a=100.0,
            pout_w=1320.0,
            pin_w=1440.0,
            temp1_c=45.0,
            fan1_rpm=3600.0,
        )
        self._snapshot()  # seeded defaults must be in lag/stuck history

    # -- helpers --------------------------------------------------------------
    @property
    def powered(self) -> bool:
        return bool(self.operation_byte & 0x80)

    def _gated(self, quantity: str) -> float:
        """Output rail quantities collapse to ~0 when OPERATION is off."""
        value = self.served(quantity)
        if not self.powered and quantity in ("vout_v", "iout_a", "pout_w"):
            return value * 0.01
        return value

    def read_command(self, reg: int, read_len: int) -> bytes:
        self.reads += 1
        if reg == PMBUS_OPERATION:
            return bytes([self.operation_byte])
        if reg == PMBUS_VOUT_MODE:
            return bytes([self.vout_mode_exponent & 0x1F])
        if reg == PMBUS_STATUS_WORD:
            status = 0x0000
            if not self.powered:
                status |= 0x0008  # PSU_STATUS_OFF (bit 3, POWER_GOOD# low)
            return struct.pack("<H", status)
        if reg == PMBUS_READ_VIN:
            return struct.pack("<H", slinear11_encode(self.served("vin_v")))
        if reg == PMBUS_READ_IIN:
            return struct.pack("<H", slinear11_encode(self.served("iin_a")))
        if reg == PMBUS_READ_VOUT:
            raw = ulinear16_encode(self._gated("vout_v"), self.vout_mode_exponent)
            return struct.pack("<H", raw)
        if reg == PMBUS_READ_IOUT:
            return struct.pack("<H", slinear11_encode(self._gated("iout_a")))
        if reg == PMBUS_READ_TEMPERATURE_1:
            return struct.pack("<H", slinear11_encode(self.served("temp1_c")))
        if reg == PMBUS_READ_FAN_SPEED_1:
            return struct.pack("<H", slinear11_encode(self.served("fan1_rpm")))
        if reg == PMBUS_READ_POUT:
            return struct.pack("<H", slinear11_encode(self._gated("pout_w")))
        if reg == PMBUS_READ_PIN:
            return struct.pack("<H", slinear11_encode(self.served("pin_w")))
        if reg == PMBUS_MFR_ID:
            return b"EMU-TWIN"
        if reg == PMBUS_MFR_MODEL:
            return b"APW-TWIN"
        if reg == PMBUS_MFR_REVISION:
            return b"0.1"
        raise SidecarError("nack", f"PMBus command 0x{reg:02X} not implemented")

    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        self.writes += 1
        if reg == PMBUS_OPERATION:
            if not values:
                raise SidecarError("bad-request", "OPERATION needs a payload byte")
            self.operation_byte = values[0] & 0xFF
            return
        raise SidecarError(
            "unsupported",
            f"PMBus write 0x{(reg or 0):02X} refused: twin sidecar is telemetry-semantics only",
        )


# ---------------------------------------------------------------------------
# APW12 SMBus PSU (0x10) — opcode-as-register protocol
# ---------------------------------------------------------------------------


class Apw12Psu(EmuDevice):
    kind = "apw12-smbus-psu"

    def __init__(self, name: str = "apw12", address: int = APW12_ADDR) -> None:
        super().__init__(name, [address])
        self.powered = False
        self.commanded_mv = 0
        self.watchdog_enabled = False
        self._truth.update(actual_mv=0, input_v=220.0, output_a=0.0, output_w=0.0, temp_c=40.0)
        self._snapshot()  # seeded defaults must be in lag/stuck history

    def read_command(self, reg: int, read_len: int) -> bytes:
        """``reg`` is the APW12 opcode byte."""
        self.reads += 1
        opcode = reg & 0xFF
        if opcode == 0x03:  # READ_VOLTAGE → millivolts LE
            mv = int(round(self.served("actual_mv")))
            return struct.pack("<H", max(0, min(0xFFFF, mv)))
        if opcode == 0x04:  # GET_FW_VERSION → 0x0103 LE
            return struct.pack("<H", APW12_FW_VERSION)
        if opcode == 0x05:  # READ_TELEMETRY → 32-byte block
            return self._telemetry_block()
        if opcode == 0x08:  # GET_HW_VERSION
            return struct.pack("<H", 0x0001)
        if opcode == 0x09:  # CALIB_STATUS → ready
            return bytes([0x01])
        if opcode == 0x0A:  # GET_AC_POWER
            return struct.pack("<H", 1 if self.powered else 0)
        if opcode == 0x0B:  # READ_ERROR_CODE
            return bytes([0x00])
        if opcode == 0x0C:  # READ_ERROR_DATA
            return bytes([0x00, 0x00])
        if opcode == 0x0D:  # GET_UPDATE_TIME
            return struct.pack("<H", int(time.time()) & 0xFFFF)
        if opcode == 0x0E:  # GET_RESET_CAUSE
            return bytes([0x01])
        if opcode == 0x10:  # GET_POWER_SN
            return b"EMU-TWIN-APW12"
        raise SidecarError("nack", f"APW12 opcode 0x{opcode:02X} not implemented")

    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        """APW12 writes are opcode + optional payload (reg = opcode)."""
        self.writes += 1
        opcode = (reg if reg is not None else 0x00) & 0xFF
        if opcode == 0x00:  # POWER_OFF
            self.powered = False
            self._truth.update(actual_mv=0.0, output_a=0.0, output_w=0.0)
            self._snapshot()
            return
        if opcode == 0x01:  # POWER_ON
            self.powered = True
            self._truth.update(
                actual_mv=float(self.commanded_mv),
                output_a=100.0 if self.commanded_mv else 0.0,
                output_w=132.0 if self.commanded_mv else 0.0,
            )
            self._snapshot()
            return
        if opcode == 0x02:  # SET_VOLTAGE: payload = millivolts LE
            if len(values) < 2:
                raise SidecarError("bad-request", "SET_VOLTAGE needs a 2-byte mV payload")
            mv = struct.unpack("<H", bytes(values[:2]))[0]
            if mv > APW12_VOLTAGE_MAX_MV:
                raise SidecarError("bad-request", f"SET_VOLTAGE {mv} mV exceeds VOLTAGE_MAX_MV")
            self.commanded_mv = mv
            return
        if opcode == 0x06:  # ENABLE_WDOG: payload ms LE
            self.watchdog_enabled = True
            return
        if opcode == 0x07:  # DISABLE_WDOG
            self.watchdog_enabled = False
            return
        if opcode == 0x0F:  # CLEAR_FAULTS
            return
        raise SidecarError("nack", f"APW12 write opcode 0x{opcode:02X} not implemented")

    def _telemetry_block(self) -> bytes:
        block = bytearray(APW12_TELEMETRY_BLOCK_LEN)
        struct.pack_into("<H", block, 0, int(round(self.served("actual_mv"))))  # [0:2] mV
        struct.pack_into("<H", block, 2, int(round(self.served("input_v") * 10)))  # [2:4] V*10
        struct.pack_into("<H", block, 4, int(round(self.served("output_a") * 10)))  # [4:6] A*10
        struct.pack_into("<H", block, 6, int(round(self.served("output_w") * 10)))  # [6:8] W*10
        struct.pack_into("<H", block, 8, int(round(self.served("temp_c") * 10)))  # [8:10] C*10
        block[10] = 0x01 if self.powered else 0x00
        return bytes(block)


# ---------------------------------------------------------------------------
# EMC2305-class fan controller
# ---------------------------------------------------------------------------


class Emc2305ClassFan(EmuDevice):
    """Class-level fan controller: PWM write, tach read, 2 pulses/rev.

    Register map (documented CLASS semantics, not bit-exact EMC2305):
      0x40 + i        fan i PWM duty (byte, 0..255; write accepted)
      0x30 + 2*i      fan i tach count (16-bit BE): pulses observed in a
                      ``tach_window_s`` window; RPM = count / window * 60 /
                      PULSES_PER_REV (2).
    RPM model: rpm = max_rpm * duty / 255 (duty 0 -> 0 rpm), unless the host
    physics pushes an explicit ``rpm_i`` via set_values (measured airflow).
    """

    kind = "emc2305-class-fan"

    def __init__(
        self,
        name: str = "fanctl",
        address: int = EMC2305_CLASS_ADDR,
        fan_count: int = EMC2305_CLASS_FANS,
        max_rpm: float = 6000.0,
        tach_window_s: float = 1.0,
    ) -> None:
        super().__init__(name, [address])
        self.fan_count = fan_count
        self.max_rpm = max_rpm
        self.tach_window_s = tach_window_s
        self.pwm: List[int] = [0] * fan_count
        self._rpm_override: Dict[int, float] = {}
        for i in range(fan_count):
            self._truth[f"rpm_{i}"] = 0.0
        self._snapshot()  # seeded defaults must be in lag/stuck history

    # -- PWM write / tach read ------------------------------------------------
    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        self.writes += 1
        if reg is None or not EMC2305_PWM_BASE_REG <= reg < EMC2305_PWM_BASE_REG + self.fan_count:
            raise SidecarError("nack", f"fan PWM register 0x{reg:02X} not in 0x40..0x44")
        if len(values) < 1:
            raise SidecarError("bad-request", "PWM write needs a duty byte")
        fan = reg - EMC2305_PWM_BASE_REG
        duty = values[0] & 0xFF
        self.pwm[fan] = duty
        self._rpm_override.pop(fan, None)
        self._truth[f"rpm_{fan}"] = self.max_rpm * duty / 255.0
        self._snapshot()

    def read_command(self, reg: int, read_len: int) -> bytes:
        self.reads += 1
        base = reg - EMC2305_TACH_BASE_REG
        if base >= 0 and base % 2 == 0:
            fan = base // 2
            if 0 <= fan < self.fan_count:
                count = self._tach_count(fan)
                return struct.pack(">H", count)
        if EMC2305_PWM_BASE_REG <= reg < EMC2305_PWM_BASE_REG + self.fan_count:
            return bytes([self.pwm[reg - EMC2305_PWM_BASE_REG]])
        raise SidecarError("nack", f"fan register 0x{reg:02X} not implemented")

    def fan_rpm(self, fan: int) -> float:
        if fan in self._rpm_override:
            return self.served(f"rpm_{fan}")
        return self.served(f"rpm_{fan}")

    def _tach_count(self, fan: int) -> int:
        rpm = self.fan_rpm(fan)
        edges_per_sec = rpm / 60.0 * PULSES_PER_REV
        return int(round(edges_per_sec * self.tach_window_s))

    def set_values(self, values: Dict[str, float]) -> None:
        # explicit rpm_i from the physics model overrides the PWM-derived guess
        for key in list(values.keys()):
            if key.startswith("rpm_"):
                try:
                    fan = int(key.split("_", 1)[1])
                except ValueError:
                    continue
                self._rpm_override[fan] = float(values[key])
        super().set_values(values)


# ---------------------------------------------------------------------------
# LM75 temperature sensors
# ---------------------------------------------------------------------------


class Lm75(EmuDevice):
    kind = "lm75"

    def __init__(self, name: str, address: int, temp_c: float = 30.0) -> None:
        super().__init__(name, [address])
        self._truth.update(temp_c=temp_c, thyst_c=75.0, tos_c=80.0)
        self._snapshot()  # seeded defaults must be in lag/stuck history
        self.config = 0x00

    def read_command(self, reg: int, read_len: int) -> bytes:
        self.reads += 1
        if reg == 0x00:  # temperature
            return struct.pack(">H", lm75_temp_encode(self.served("temp_c")))
        if reg == 0x01:  # config
            return bytes([self.config])
        if reg == 0x02:  # THYST
            return struct.pack(">H", lm75_temp_encode(self._truth["thyst_c"]))
        if reg == 0x03:  # TOS
            return struct.pack(">H", lm75_temp_encode(self._truth["tos_c"]))
        raise SidecarError("nack", f"LM75 register 0x{reg:02X} not implemented")

    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        self.writes += 1
        if reg == 0x01 and values:
            self.config = values[0] & 0xFF
            return
        if reg in (0x02, 0x03) and len(values) >= 2:
            raw = struct.unpack(">H", bytes(values[:2]))[0]
            self._truth["thyst_c" if reg == 0x02 else "tos_c"] = lm75_temp_decode(raw)
            self._snapshot()
            return
        raise SidecarError("nack", f"LM75 write 0x{(reg or 0):02X} refused")


# ---------------------------------------------------------------------------
# AT24 EEPROM (0x50..0x57) — G1 write-denylist semantics
# ---------------------------------------------------------------------------


class At24Eeprom(EmuDevice):
    """EEPROM image server whose WRITES ARE ALWAYS REFUSED.

    The production HAL registers the per-bus write denylist ``[0x50..=0x57]``
    (am2 policy) at platform startup; the daemon's writes fail and a counter
    increments. The sidecar mirrors the DEVICE side of that invariant so the
    twin can TEST G1 end-to-end: reads succeed, writes get a ``denied`` error,
    and ``stats.eeprom_write_denied`` counts every refusal. The twin never
    bypasses its own safety gate.
    """

    kind = "at24-eeprom"

    def __init__(
        self,
        name: str,
        address: int,
        preamble_byte: int = 0x04,
        page_len: int = EEPROM_PAGE_LEN,
    ) -> None:
        super().__init__(name, [address])
        self.image = bytearray(page_len)
        self.image[0] = preamble_byte & 0xFF  # BHB-class identity preamble
        for offset in range(1, page_len):
            self.image[offset] = (offset * 7 + address * 13) & 0xFF  # deterministic filler
        self.denied_writes = 0

    def read_command(self, reg: int, read_len: int) -> bytes:
        self.reads += 1
        offset = reg & 0xFF
        if offset + read_len > len(self.image):
            read_len = max(0, len(self.image) - offset)
        return bytes(self.image[offset : offset + read_len])

    def write_bytes(self, reg: Optional[int], values: Sequence[int]) -> None:
        self.writes += 1
        self.denied += 1
        self.denied_writes += 1
        raise SidecarError(
            "denied",
            f"EEPROM write denylist (G1): address 0x{self.addresses[0]:02X} is write-protected",
        )

    def raw_exchange(self, tx: bytes) -> bytes:
        if len(tx) >= 1:
            # any write phase in a raw transaction is still a denied write
            self.writes += 1
            self.denied += 1
            self.denied_writes += 1
            raise SidecarError(
                "denied",
                f"EEPROM write denylist (G1): address 0x{self.addresses[0]:02X} is write-protected",
            )
        raise SidecarError("bad-request", "raw EEPROM op needs at least an offset byte")


# ---------------------------------------------------------------------------
# dsPIC voltage controller (framed presence stub)
# ---------------------------------------------------------------------------


class Dspic(EmuDevice):
    """Framed dsPIC presence stub: 55 AA opcodes over raw exchanges.

    Response shapes are minimal presence acknowledgements (documented in
    sidecar_protocol.md); exact byte-for-byte frame truth lands with the wire
    module / held-captures PoC. The fw byte is selectable so twin scenarios
    can drive the daemon's fw=0x86 refusal path (G2) versus 0x89 admission.
    """

    kind = "dspic-framed"

    def __init__(self, name: str, address: int, fw: int = DSPIC_FW_DEFAULT) -> None:
        super().__init__(name, [address])
        self.fw = fw & 0xFF
        self.enabled = False
        self.heartbeats = 0

    def raw_exchange(self, tx: bytes) -> bytes:
        self.reads += 1
        if tx == DSPIC_GET_VERSION:
            return bytes([0xAA, 0x55, self.fw])
        if tx == DSPIC_ENABLE:
            self.enabled = True
            return bytes([0xAA, 0x55, 0x01])
        if tx == DSPIC_HEARTBEAT:
            self.heartbeats += 1
            return bytes([0xAA, 0x55, 0x01])
        raise SidecarError("nack", f"unsupported dsPIC frame {tx.hex()}")

    def set_fw(self, fw: int) -> None:
        self.fw = fw & 0xFF


# ---------------------------------------------------------------------------
# Sidecar service
# ---------------------------------------------------------------------------


def _parse_int(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise SidecarError("bad-request", f"{field} must be an int or hex string")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower().replace("0x", "")
        try:
            return int(text, 16 if value.strip().lower().startswith("0x") else 10)
        except ValueError:
            try:
                return int(text, 16)
            except ValueError as exc:
                raise SidecarError("bad-request", f"{field}: bad value {value!r}") from exc
    raise SidecarError("bad-request", f"{field} must be an int or hex string")


class I2cSidecar:
    """Threaded localhost TCP front for the emulated I2C devices."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        lm75_addresses: Sequence[int] = (0x48, 0x49, 0x4A, 0x4B),
        eeprom_addresses: Sequence[int] = tuple(range(EEPROM_FIRST_ADDR, EEPROM_LAST_ADDR + 1)),
        dspic_addresses: Sequence[int] = DSPIC_ADDRS,
        fan_address: int = EMC2305_CLASS_ADDR,
    ) -> None:
        self.host = host
        self._requested_port = port
        self._lock = threading.Lock()
        self.devices: Dict[str, EmuDevice] = {}
        self._by_addr: Dict[int, EmuDevice] = {}

        self._add(PmbusPsu())
        self._add(PmbusPsu(name="psu_alt", address=PMBUS_ADDR_ALT))
        self._add(Apw12Psu())
        for addr in lm75_addresses:
            self._add(Lm75(f"lm75_{addr:02x}", addr))
        for addr in eeprom_addresses:
            self._add(At24Eeprom(f"eeprom_{addr:02x}", addr))
        for addr in dspic_addresses:
            self._add(Dspic(f"dspic_{addr:02x}", addr))
        self._add(Emc2305ClassFan(address=fan_address))

        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None
        self.ops_served = 0

    # -- setup ----------------------------------------------------------------
    def _add(self, device: EmuDevice) -> None:
        self.devices[device.name] = device
        for addr in device.addresses:
            if addr in self._by_addr:
                raise ValueError(f"address conflict 0x{addr:02X}")
            self._by_addr[addr] = device

    def start(self) -> "I2cSidecar":
        if self._server is not None:
            return self
        self._server = _SidecarServer((self.host, self._requested_port), self)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="i2c-sidecar", daemon=True
        )
        self._thread.start()
        self._port = self._server.server_address[1]
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
        self._port = None

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("sidecar not started")
        return self._port

    @property
    def url(self) -> str:
        return f"tcp://{self.host}:{self.port}"

    def device_at(self, addr: int) -> EmuDevice:
        device = self._by_addr.get(addr)
        if device is None:
            raise SidecarError("nack", f"no device at address 0x{addr:02X}")
        return device

    # -- stats ------------------------------------------------------------------
    def stats(self) -> Dict[str, object]:
        with self._lock:
            return {
                "url": self.url if self._port else None,
                "ops_served": self.ops_served,
                "eeprom_write_denied": sum(
                    getattr(d, "denied_writes", 0)
                    for d in self.devices.values()
                    if isinstance(d, At24Eeprom)
                ),
                "devices": {name: dev.describe() for name, dev in self.devices.items()},
            }

    # -- op dispatch (shared by TCP handler and in-process callers) -------------
    def handle_op(self, request: Dict[str, object]) -> Dict[str, object]:
        """Execute one protocol op; returns the ``result`` payload.

        Raises SidecarError for protocol failures. ``id`` is echoed by the
        TCP layer, not here.
        """
        op = str(request.get("op", ""))
        with self._lock:
            self.ops_served += 1
        if op == "probe":
            return {"devices": [dev.describe() for dev in self.devices.values()]}
        if op == "stats":
            return self.stats()
        if op == "read" or op == "write_read":
            return self._op_read(request, write_read=op == "write_read")
        if op == "write":
            return self._op_write(request)
        if op == "raw":
            return self._op_raw(request)
        if op == "set_values":
            return self._op_set_values(request)
        if op == "set_fw":
            return self._op_set_fw(request)
        if op == "inject":
            return self._op_inject(request)
        if op == "clear_injectors":
            return self._op_clear_injectors(request)
        if op == "reset":
            return self._op_reset()
        raise SidecarError("bad-request", f"unknown op {op!r}")

    def _device_from_request(self, request: Dict[str, object]) -> EmuDevice:
        if "addr" in request:
            addr = _parse_int(request["addr"], "addr")
            return self.device_at(addr & 0x7F)
        if "device" in request:
            name = str(request["device"])
            if name not in self.devices:
                raise SidecarError("unknown-device", f"no device named {name!r}")
            return self.devices[name]
        raise SidecarError("bad-request", "need 'addr' or 'device'")

    def _op_read(self, request: Dict[str, object], write_read: bool) -> Dict[str, object]:
        device = self._device_from_request(request)
        reg = _parse_int(request["reg"], "reg") & 0xFF
        if write_read:
            read_len = int(_parse_int(request.get("read_len", 2), "read_len"))
        else:
            width = str(request.get("width", "word")).lower()
            read_len = {"byte": 1, "word": 2, "block": int(request.get("length", 32))}[width]
        data = device.read_command(reg, read_len)
        result: Dict[str, object] = {
            "device": device.name,
            "kind": device.kind,
            "reg": f"0x{reg:02X}",
            "bytes": list(data),
            "hex": data.hex(),
        }
        if device.kind == "pmbus-psu":
            result["decoded"] = self._decode_pmbus(reg, data)
        if device.kind == "lm75" and reg == 0x00:
            raw = struct.unpack(">H", data)[0]
            result["decoded"] = {"temp_c": lm75_temp_decode(raw)}
        return result

    @staticmethod
    def _decode_pmbus(reg: int, data: bytes) -> Dict[str, object]:
        if len(data) < 2:
            if reg == PMBUS_VOUT_MODE:
                return {"exponent": extend_pmbus_exponent(data[0] & 0x1F)}
            return {}
        word = struct.unpack("<H", data[:2])[0]
        if reg == PMBUS_READ_VOUT:
            # decode needs VOUT_MODE; caller should read 0x20 first — the
            # sidecar returns the raw ULINEAR16 mantissa plus the live
            # exponent so the value is self-describing.
            return {"ulinear16_raw": word}
        if reg in (
            PMBUS_READ_VIN,
            PMBUS_READ_IIN,
            PMBUS_READ_IOUT,
            PMBUS_READ_TEMPERATURE_1,
            PMBUS_READ_FAN_SPEED_1,
            PMBUS_READ_POUT,
            PMBUS_READ_PIN,
        ):
            return {"slinear11": slinear11_decode(word)}
        if reg == PMBUS_STATUS_WORD:
            return {"status_word": word}
        return {"text": data.decode("ascii", errors="replace")}

    def _op_write(self, request: Dict[str, object]) -> Dict[str, object]:
        device = self._device_from_request(request)
        reg_field = request.get("reg")
        reg = None if reg_field is None else _parse_int(reg_field, "reg") & 0xFF
        values_field = request.get("values", [])
        if not isinstance(values_field, list):
            raise SidecarError("bad-request", "values must be a list of bytes")
        values = [int(v) & 0xFF for v in values_field]
        device.write_bytes(reg, values)
        return {"device": device.name, "kind": device.kind, "written": len(values)}

    def _op_raw(self, request: Dict[str, object]) -> Dict[str, object]:
        device = self._device_from_request(request)
        tx_hex = str(request.get("tx_hex", ""))
        try:
            tx = bytes.fromhex(tx_hex)
        except ValueError as exc:
            raise SidecarError("bad-request", f"tx_hex: {exc}") from exc
        rx = device.raw_exchange(tx)
        return {"device": device.name, "rx_hex": rx.hex()}

    def _op_set_values(self, request: Dict[str, object]) -> Dict[str, object]:
        device = self._device_from_request(request)
        values = request.get("values")
        if not isinstance(values, dict):
            raise SidecarError("bad-request", "values must be an object")
        device.set_values({str(k): v for k, v in values.items()})
        return {"device": device.name, "values": dict(device._truth)}

    def _op_set_fw(self, request: Dict[str, object]) -> Dict[str, object]:
        device = self._device_from_request(request)
        if not isinstance(device, Dspic):
            raise SidecarError("bad-request", "set_fw applies to dsPIC devices only")
        fw = _parse_int(request.get("fw", DSPIC_FW_DEFAULT), "fw") & 0xFF
        device.set_fw(fw)
        return {"device": device.name, "fw": device.fw}

    def _op_inject(self, request: Dict[str, object]) -> Dict[str, object]:
        device = self._device_from_request(request)
        kind = str(request.get("kind", ""))
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise SidecarError("bad-request", "params must be an object")
        device.inject(kind, params)
        return {"device": device.name, "injectors": device.injector_state()}

    def _op_clear_injectors(self, request: Dict[str, object]) -> Dict[str, object]:
        target = str(request.get("device", "all"))
        cleared: List[str] = []
        if target == "all":
            for device in self.devices.values():
                device.clear_injectors()
                cleared.append(device.name)
        else:
            if target not in self.devices:
                raise SidecarError("unknown-device", f"no device named {target!r}")
            self.devices[target].clear_injectors()
            cleared.append(target)
        return {"cleared": cleared}

    def _op_reset(self) -> Dict[str, object]:
        for device in self.devices.values():
            device.clear_injectors()
            device.reads = 0
            device.writes = 0
            device.denied = 0
            if isinstance(device, At24Eeprom):
                device.denied_writes = 0
        return {"reset": True}


class _SidecarServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, sidecar: I2cSidecar) -> None:
        self.sidecar = sidecar
        super().__init__(address, _SidecarHandler)


class _SidecarHandler(socketserver.StreamRequestHandler):
    """One JSON-lines sidecar connection."""

    def handle(self) -> None:
        sidecar: I2cSidecar = self.server.sidecar  # type: ignore[attr-defined]
        while True:
            line = self.rfile.readline(64 * 1024)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                request = json.loads(text)
                if not isinstance(request, dict):
                    raise SidecarError("bad-request", "request must be a JSON object")
            except json.JSONDecodeError:
                self._send(None, ok=False, error="invalid JSON", code="bad-request")
                continue
            request_id = request.get("id")
            try:
                result = sidecar.handle_op(request)
                self._send(request_id, ok=True, result=result)
            except SidecarError as exc:
                self._send(request_id, ok=False, error=str(exc), code=exc.code)
            except (ValueError, KeyError, TypeError) as exc:
                self._send(request_id, ok=False, error=f"bad request: {exc}", code="bad-request")

    def _send(self, request_id: object, ok: bool, **fields: object) -> None:
        payload = {"id": request_id, "ok": ok}
        payload.update(fields)
        try:
            self.wfile.write((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="emu-twin host-side I2C device sidecar (PMBus/APW12/LM75/EEPROM-G1/dsPIC/fan)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (localhost only)")
    parser.add_argument("--port", type=int, default=17003, help="bind port (0 = ephemeral)")
    args = parser.parse_args(argv)

    sidecar = I2cSidecar(host=args.host, port=args.port).start()
    print(f"i2c sidecar listening on {sidecar.url} (contract: sidecar_protocol.md)")
    print("devices: " + ", ".join(sorted(sidecar.devices)))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        print(json.dumps({"eeprom_write_denied": sidecar.stats()["eeprom_write_denied"]}))
        sidecar.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
