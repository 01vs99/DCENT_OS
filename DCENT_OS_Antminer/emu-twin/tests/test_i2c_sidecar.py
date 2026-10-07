"""Tests for the emu-twin I2C sidecar (I2-owned).

Covers: PMBus numeric encodings, PMBus/APW12/LM75/fan/dsPIC/EEPROM semantics
over the documented TCP contract, the G1 EEPROM write-denylist (every address
0x50..0x57 must refuse writes — this is the twin TESTING the invariant, not
bypassing it), and the three fault injectors (lag / lie / stuck, default OFF).
"""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import i2c_sidecar
from i2c_sidecar import (
    APW12_FW_VERSION,
    DSPIC_FW_DEFAULT,
    EEPROM_PAGE_LEN,
    I2cSidecar,
    SidecarError,
    lm75_temp_decode,
    lm75_temp_encode,
    slinear11_decode,
    slinear11_encode,
    ulinear16_encode,
)


class SidecarClient:
    """JSON-lines TCP client for the sidecar contract."""

    def __init__(self, port: int, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()
        self._id = 0

    def close(self) -> None:
        self.sock.close()

    def op(self, op: str, **fields) -> dict:
        self._id += 1
        request = {"id": self._id, "op": op}
        request.update(fields)
        self.sock.sendall((json.dumps(request) + "\n").encode())
        while True:
            line = b""
            while b"\n" not in self._buf:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError("sidecar closed")
                self._buf.extend(chunk)
            raw, _, rest = self._buf.partition(b"\n")
            self._buf = bytearray(rest)
            text = raw.decode().strip()
            if text:
                response = json.loads(text)
                if response.get("id") == self._id:
                    return response


@pytest.fixture()
def sidecar():
    service = I2cSidecar().start()
    yield service
    service.stop()


@pytest.fixture()
def client(sidecar):
    conn = SidecarClient(sidecar.port)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# PMBus numeric encodings (pmbus.rs SLINEAR11 / ULINEAR16)
# ---------------------------------------------------------------------------


class TestPmbusEncodings:
    @pytest.mark.parametrize(
        "value",
        [0.0, 1.0, 13.2, 45.0, 100.0, 230.0, 1320.0, 3600.0, -12.5, 0.5, 1440.0, 7.2],
    )
    def test_slinear11_roundtrip_within_half_step(self, value):
        word = slinear11_encode(value)
        decoded = slinear11_decode(word)
        step = 2.0 ** ((word >> 11) & 0x1F)
        # signed-exponent roundtrip: decode = mantissa * 2^exp, error < step
        if value == 0:
            assert decoded == 0
        else:
            assert abs(decoded - value) <= step / 2 + 1e-9
            # encoder must have chosen a representable mantissa
            mantissa = word & 0x7FF
            assert mantissa <= 0x7FF

    def test_slinear11_known_word(self):
        # 100.0 A encodes as mantissa 800, exponent -3 -> 800 * 2^-3
        word = slinear11_encode(100.0)
        assert (word >> 11) & 0x1F == ( -3 ) & 0x1F
        assert word & 0x7FF == 800

    def test_ulinear16_vout(self):
        exponent = -9
        raw = ulinear16_encode(13.2, exponent)
        assert raw == 6758  # round(13.2 * 512)
        assert raw * (2.0 ** exponent) == pytest.approx(13.2, abs=2 ** -10)

    def test_lm75_roundtrip(self):
        raw = lm75_temp_encode(42.5)
        assert raw == 0x2A80  # 42.5 * 256
        assert lm75_temp_decode(raw) == 42.5
        assert lm75_temp_decode(lm75_temp_encode(-10.25)) == -10.25


# ---------------------------------------------------------------------------
# TCP contract: devices
# ---------------------------------------------------------------------------


class TestProbeAndStats:
    def test_probe_lists_expected_devices(self, client):
        response = client.op("probe")
        assert response["ok"] is True
        kinds = {d["kind"] for d in response["result"]["devices"]}
        assert kinds >= {
            "pmbus-psu",
            "apw12-smbus-psu",
            "at24-eeprom",
            "lm75",
            "dspic-framed",
            "emc2305-class-fan",
        }


class TestPmbusPsu:
    def test_readback_values_sane(self, client):
        vout_mode = client.op("read", addr="0x58", reg="0x20", width="byte")
        assert vout_mode["ok"] is True
        exponent = i2c_sidecar.extend_pmbus_exponent(vout_mode["result"]["bytes"][0])
        assert exponent == -9

        vout = client.op("read", addr="0x58", reg="0x8B", width="word")  # READ_VOUT
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        assert raw * (2.0 ** exponent) == pytest.approx(13.2, abs=2 ** -9)

        iout = client.op("read", addr="0x58", reg="0x8C", width="word")  # READ_IOUT
        assert iout["result"]["decoded"]["slinear11"] == pytest.approx(100.0, abs=0.5)

        pout = client.op("read", addr="0x58", reg="0x96", width="word")  # READ_POUT
        assert pout["result"]["decoded"]["slinear11"] == pytest.approx(1320.0, abs=4.0)

        vin = client.op("read", addr="0x58", reg="0x88", width="word")  # READ_VIN
        assert vin["result"]["decoded"]["slinear11"] == pytest.approx(230.0, abs=1.0)

    def test_physics_set_values_drive_telemetry(self, client, sidecar):
        client.op("set_values", device="psu", values={"vout_v": 13.05, "iout_a": 98.5})
        vout = client.op("read", addr="0x58", reg="0x8B", width="word")
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        assert raw * (2.0 ** -9) == pytest.approx(13.05, abs=2 ** -9)
        iout = client.op("read", addr="0x58", reg="0x8C", width="word")
        assert iout["result"]["decoded"]["slinear11"] == pytest.approx(98.5, abs=0.5)

    def test_operation_gates_output_rails(self, client):
        assert client.op("write", addr="0x58", reg="0x01", values=[0x00])["ok"] is True
        vout = client.op("read", addr="0x58", reg="0x8B", width="word")
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        assert raw * (2.0 ** -9) < 1.0  # rail collapsed when OPERATION = off
        status = client.op("read", addr="0x58", reg="0x79", width="word")
        assert status["result"]["decoded"]["status_word"] & 0x0008  # PSU_STATUS_OFF
        client.op("write", addr="0x58", reg="0x01", values=[0x80])  # back on

    def test_non_operation_writes_refused(self, client):
        response = client.op("write", addr="0x58", reg="0x96", values=[0, 0])
        assert response["ok"] is False
        assert response["code"] == "unsupported"


class TestApw12:
    def test_fw_version_word_is_0103_le(self, client):
        response = client.op("write_read", addr="0x10", reg="0x04", read_len=2)
        assert response["ok"] is True
        assert response["result"]["bytes"] == [APW12_FW_VERSION & 0xFF, APW12_FW_VERSION >> 8]

    def test_set_voltage_uses_daemon_test_vector_millivolts(self, client):
        # daemon test pins the SET_VOLTAGE payload [0x02, 0x8C, 0x05] = 1420 mV
        response = client.op("write", addr="0x10", reg="0x02", values=[0x8C, 0x05])
        assert response["ok"] is True
        assert client.op("write", addr="0x10", reg="0x01", values=[])["ok"] is True  # POWER_ON
        voltage = client.op("write_read", addr="0x10", reg="0x03", read_len=2)
        assert voltage["result"]["bytes"] == [0x8C, 0x05]

    def test_set_voltage_over_voltage_max_refused(self, client):
        response = client.op("write", addr="0x10", reg="0x02", values=[0xA0, 0x06])  # 0x06A0=1696mV
        assert response["ok"] is False
        assert response["code"] == "bad-request"

    def test_telemetry_block_length(self, client):
        response = client.op("read", addr="0x10", reg="0x05", width="block", length=32)
        assert response["ok"] is True
        assert len(response["result"]["bytes"]) == i2c_sidecar.APW12_TELEMETRY_BLOCK_LEN


class TestLm75:
    def test_temperature_register_roundtrip(self, client):
        assert client.op("set_values", device="lm75_48", values={"temp_c": 42.5})["ok"]
        response = client.op("read", addr="0x48", reg="0x00", width="word")
        assert response["ok"] is True
        assert response["result"]["bytes"] == [0x2A, 0x80]  # big-endian, 42.5 C
        assert response["result"]["decoded"]["temp_c"] == 42.5

    def test_unknown_register_nacks(self, client):
        response = client.op("read", addr="0x48", reg="0x7F", width="byte")
        assert response["ok"] is False
        assert response["code"] == "nack"


class TestEmc2305ClassFan:
    def test_pwm_write_and_two_pulses_per_rev_tach(self, client):
        # command 100% duty on fan 0 -> model rpm exactly 6000
        assert client.op("write", addr="0x2F", reg="0x40", values=[255])["ok"]
        tach = client.op("read", addr="0x2F", reg="0x30", width="word")
        count_bytes = tach["result"]["bytes"]
        count = (count_bytes[0] << 8) | count_bytes[1]
        # edges/s = rpm/60 * 2 pulses/rev; count over the 1 s window == edges/s
        assert count == round(6000.0 / 60.0 * 2 * 1.0)
        # guest-side inversion: rpm = count * 60 / window / PULSES_PER_REV
        assert count * 60.0 / 1.0 / 2 == 6000.0

    def test_half_duty_tach_count_rounds_correctly(self, client):
        assert client.op("write", addr="0x2F", reg="0x40", values=[128])["ok"]
        tach = client.op("read", addr="0x2F", reg="0x30", width="word")
        count_bytes = tach["result"]["bytes"]
        count = (count_bytes[0] << 8) | count_bytes[1]
        expected_rpm = 6000.0 * 128 / 255.0
        assert count == round(expected_rpm / 60.0 * 2 * 1.0)
        # inversion is exact within one count quantum (30 rpm at 2 ppr / 1 s)
        assert count * 60.0 / 1.0 / 2 == pytest.approx(expected_rpm, abs=31.0)

    def test_zero_duty_means_zero_rpm(self, client):
        assert client.op("write", addr="0x2F", reg="0x41", values=[0])["ok"]
        tach = client.op("read", addr="0x2F", reg="0x32", width="word")  # fan 1 tach
        count_bytes = tach["result"]["bytes"]
        assert (count_bytes[0] << 8) | count_bytes[1] == 0

    def test_pwm_readback(self, client):
        assert client.op("write", addr="0x2F", reg="0x42", values=[200])["ok"]
        readback = client.op("read", addr="0x2F", reg="0x42", width="byte")
        assert readback["result"]["bytes"] == [200]


# ---------------------------------------------------------------------------
# G1: EEPROM write denylist — the twin TESTS the invariant
# ---------------------------------------------------------------------------


class TestEepromDenylist:
    def test_every_address_50_to_57_refuses_writes(self, client):
        for addr in range(0x50, 0x58):
            response = client.op("write", addr=addr, reg="0x00", values=[0xFF, 0xFF])
            assert response["ok"] is False, f"write to 0x{addr:02X} must be refused"
            assert response["code"] == "denied"
            assert "denylist" in response["error"].lower() or "g1" in response["error"].lower()

    def test_denied_count_matches_every_refusal(self, client):
        before = client.op("stats")["result"]["eeprom_write_denied"]
        for addr in (0x50, 0x51, 0x57):
            client.op("write", addr=addr, reg="0x10", values=[0x00])
        after = client.op("stats")["result"]["eeprom_write_denied"]
        assert after == before + 3

    def test_reads_still_work_with_bhb_preamble(self, client):
        response = client.op("read", addr="0x51", reg="0x00", width="block", length=32)
        assert response["ok"] is True
        data = response["result"]["bytes"]
        assert len(data) == 32
        assert data[0] == 0x04  # BHB-class identity preamble

    def test_raw_exchange_also_denied(self, client):
        response = client.op("raw", addr="0x50", tx_hex="0011")
        assert response["ok"] is False
        assert response["code"] == "denied"

    def test_full_page_read_deterministic(self, client):
        first = client.op("read", addr="0x52", reg="0x00", width="block", length=256)
        second = client.op("read", addr="0x52", reg="0x00", width="block", length=256)
        assert first["result"]["bytes"] == second["result"]["bytes"]
        assert len(first["result"]["bytes"]) == EEPROM_PAGE_LEN


class TestDspic:
    def test_get_version_default_fw(self, client):
        response = client.op("raw", addr="0x20", tx_hex="55aa17")
        assert response["ok"] is True
        assert response["result"]["rx_hex"] == f"aa55{DSPIC_FW_DEFAULT:02x}"

    def test_set_fw_86_selects_g2_refusal_scenario(self, client):
        assert client.op("set_fw", addr="0x21", fw=0x86)["ok"] is True
        response = client.op("raw", addr="0x21", tx_hex="55aa17")
        assert response["result"]["rx_hex"] == "aa5586"

    def test_enable_and_heartbeat_frames_ack(self, client, sidecar):
        response = client.op("raw", addr="0x22", tx_hex="55aa041501")
        assert response["ok"] is True
        assert response["result"]["rx_hex"] == "aa5501"
        response = client.op("raw", addr="0x22", tx_hex="55aa041600")
        assert response["result"]["rx_hex"] == "aa5501"
        assert sidecar.devices["dspic_22"].heartbeats == 1

    def test_unknown_frame_nacks(self, client):
        response = client.op("raw", addr="0x20", tx_hex="deadbeef")
        assert response["ok"] is False
        assert response["code"] == "nack"


class TestUnknownDevice:
    def test_unpopulated_address_nacks(self, client):
        response = client.op("read", addr="0x33", reg="0x00", width="byte")
        assert response["ok"] is False
        assert response["code"] == "nack"


# ---------------------------------------------------------------------------
# Fault injectors (default OFF; feed the tuner fault-injection suite)
# ---------------------------------------------------------------------------


class TestFaultInjectors:
    def test_defaults_off_truth_equals_served(self, sidecar):
        psu = sidecar.devices["psu"]
        psu.set_values({"vout_v": 13.1})
        assert psu.served("vout_v") == psu.truth("vout_v") == 13.1

    def test_readback_lie_scales_only_selected_quantities(self, client):
        assert client.op(
            "inject", device="psu", kind="readback_lie",
            params={"scale": 1.1, "quantities": ["vout_v"]},
        )["ok"]
        vout = client.op("read", addr="0x58", reg="0x8B", width="word")
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        assert raw * (2.0 ** -9) == pytest.approx(13.2 * 1.1, abs=2 ** -8)
        iout = client.op("read", addr="0x58", reg="0x8C", width="word")
        assert iout["result"]["decoded"]["slinear11"] == pytest.approx(100.0, abs=0.5)

    def test_readback_lag_serves_stale_history(self, client):
        assert client.op("inject", device="psu", kind="readback_lag",
                         params={"seconds": 3600.0})["ok"]
        client.op("set_values", device="psu", values={"vout_v": 15.0})
        vout = client.op("read", addr="0x58", reg="0x8B", width="word")
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        # 1-hour lag: the read serves the pre-change truth (13.2), not 15.0
        assert raw * (2.0 ** -9) == pytest.approx(13.2, abs=2 ** -9)

    def test_stuck_value_freezes_at_arm_time(self, client):
        assert client.op("set_values", device="lm75_49", values={"temp_c": 31.0})["ok"]
        assert client.op("inject", device="lm75_49", kind="stuck_value")["ok"]
        client.op("set_values", device="lm75_49", values={"temp_c": 55.0})
        temp = client.op("read", addr="0x49", reg="0x00", width="word")
        assert temp["result"]["decoded"]["temp_c"] == 31.0  # frozen, not 55

    def test_clear_injectors_restores_live_truth(self, client):
        client.op("inject", device="psu", kind="readback_lie", params={"scale": 1.5})
        assert client.op("clear_injectors", device="psu")["ok"]
        vout = client.op("read", addr="0x58", reg="0x8B", width="word")
        raw = vout["result"]["decoded"]["ulinear16_raw"]
        assert raw * (2.0 ** -9) == pytest.approx(13.2, abs=2 ** -9)

    def test_reset_keeps_the_denylist_engaged(self, client):
        client.op("write", addr="0x55", reg="0x00", values=[1])
        assert client.op("reset")["ok"]
        stats = client.op("stats")["result"]
        assert stats["eeprom_write_denied"] == 0  # counters reset...
        denied = client.op("write", addr="0x55", reg="0x00", values=[1])
        assert denied["ok"] is False  # ...but the denylist itself survives


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestProtocolRobustness:
    def test_bad_json_gets_error_response_not_disconnect(self, sidecar):
        conn = SidecarClient(sidecar.port)
        try:
            conn.sock.sendall(b"not json\n")
            response = conn.op("probe")  # connection still usable
            assert response["ok"] is True
        finally:
            conn.close()

    def test_unknown_op_is_bad_request(self, client):
        response = client.op("frobnicate")
        assert response["ok"] is False
        assert response["code"] == "bad-request"
