# emu-twin I2C Sidecar Protocol (host-side semantics)

Owner: I2 (campaign , wave 3).
Implementation: `DCENT_OS_Antminer/emu-twin/i2c_sidecar.py`. Date: 2026-10-05.

## Scope and the C1-F1 fold (read this first)

**The guest-attachment mechanism for I2C is UNRESOLVED — host-side semantics
are the deliverable.** Campaign fold C1-F1 (critical) established that the
A2 plan's "daemon I2C works against `i2c-stub` unmodified" is FALSE:

- `dcentrald-hal/src/i2c.rs` performs raw `I2C_RDWR` ioctls (const `0x0707`).
- Linux `i2c-stub` implements only `.smbus_xfer` and does not declare
  `I2C_FUNC_I2C`, so every `I2C_RDWR` ioctl against it returns `-EOPNOTSUPP`.
- The HAL has **no SMBus-ioctl path at all** (zero `I2C_SMBUS` references).

Therefore this sidecar is a **host-side device-semantics service** speaking
the TCP contract below. It does not speak raw I2C, and nothing here claims
T2 (real-capsule) coverage of I2C-dependent behavior. Per plan.md §11 C1-F1,
until a guest facility is proven, dsPIC / EEPROM-denylist / LM75 / APW12
coverage stays at T1.

### Open guest-attachment PoC candidates (documented, NOT implemented)

WS2's P0.x decision gate — "prove a guest-presentable `/dev/i2c-N` that
survives one real daemon `I2C_RDWR` transaction" — must pick among:

1. **Guest-agent CUSE chardev** at the `/dev/i2c-N` path (CUSE needs
   `/dev/cuse` + a FUSE-capable userspace in a Buildroot musl guest — almost
   certainly absent from the capsule rootfs; must be verified, not assumed).
2. **virtio-i2c** — absent from the held 4.4-class guest kernels (record:
   driver too new); revisit only if a kernel rebuild happens.
3. **Patched-DTB controller models** — bind the guest to an emulated adapter
   driver that QEMU actually instantiates; requires kernel driver + DT work
   against the held 4.4 Braiins tree (same spike class as `emufpga`).
4. **Guest-agent bridge** — a small guest agent performing the ioctls itself
   against an i2c-dev–compatible backend it owns, translating to/from this
   TCP contract (the translation layer is the PoC).
5. **Documented Phase-B degradation** — V/f twin proof runs at the profile-sim
   plant (A3 L2) until one of the above ships.

Every twin evidence header must record which mechanism (if any) shipped.

## Wire contract

Transport: TCP, localhost only, newline-delimited JSON (one request object
per line, one response object per line). Same envelope as Stratum: requests
carry a client-chosen `id` echoed in the response.

### Request envelope

```json
{"id": 1, "op": "<op-name>", ...op-fields}
```

### Response envelope

```json
{"id": 1, "ok": true,  "result": {...}}
{"id": 1, "ok": false, "error": "EEPROM write denylist (G1): address 0x50 is write-protected", "code": "denied"}
```

Error `code` values: `denied` (G1 write refusal), `nack` (no device /
unsupported register), `unsupported` (device refuses the op class),
`bad-request` (malformed fields), `unknown-device`.

Addresses and registers accept ints (`16`) or hex strings (`"0x10"`).

## Operations

### `probe` / `stats` / `reset`

`probe` lists every device with kind, addresses, counters, active injectors,
and current physics-truth values. `stats` returns global counters including
**`eeprom_write_denied`** (the G1 test anchor: the count of refused EEPROM
writes across 0x50..0x57). `reset` clears injectors and counters (never the
denylist — the denylist is not disableable).

### `read` — SMBus-shaped register read

```json
{"id": 2, "op": "read", "addr": "0x58", "reg": "0x8B", "width": "word"}
```

`width`: `byte` (1), `word` (2), `block` (`length`, default 32). Semantics:
write command/pointer byte, repeated START, read — the SMBus Read shape the
daemon's `I2C_RDWR` transactions implement on real hardware. `result` carries
`bytes` (list), `hex`, and where applicable a `decoded` object.

### `write_read` — command write then read (APW12/PMBus process shape)

```json
{"id": 3, "op": "write_read", "addr": "0x10", "reg": "0x04", "read_len": 2}
```

### `write` — register write (subject to the G1 denylist)

```json
{"id": 4, "op": "write", "addr": "0x2F", "reg": "0x40", "values": [128]}
```

**Any write targeting 0x50..=0x57 returns `{"ok": false, "code": "denied"}`**
and increments `stats.eeprom_write_denied`. This is the device side of the
am2 EEPROM write-denylist invariant (HAL: per-bus denylist registered at
platform startup; reads still succeed). The twin TESTS G1 with this; there is
no override flag, by design.

### `raw` — framed exchange (dsPIC class)

```json
{"id": 5, "op": "raw", "addr": "0x20", "tx_hex": "55aa17"}
→ {"id": 5, "ok": true, "result": {"device": "dspic_20", "rx_hex": "aa5589"}}
```

### `set_values` — physics pushes device truth

```json
{"id": 6, "op": "set_values", "device": "psu", "values": {"vout_v": 13.05, "iout_a": 98.5, "pout_w": 1280.0}}
```

Also how thermal/fan models drive LM75 (`temp_c`) and fan (`rpm_0..rpm_4`)
telemetry. Injectors transform what guests READ, never the truth.

### `set_fw` — select dsPIC firmware byte (G2 scenarios)

```json
{"id": 7, "op": "set_fw", "addr": "0x20", "fw": 134}
```

`0x89` (137) = S19j admission; `0x86` (134) = degraded — the daemon's hybrid
path must refuse it (G2). The sidecar serves the byte; the twin asserts the
daemon's refusal, it never bypasses it.

### `inject` / `clear_injectors`

```json
{"id": 8, "op": "inject", "device": "psu", "kind": "readback_lie", "params": {"scale": 1.1, "quantities": ["vout_v"]}}
{"id": 9, "op": "inject", "device": "lm75_48", "kind": "readback_lag", "params": {"seconds": 5.0}}
{"id": 10, "op": "inject", "device": "psu", "kind": "stuck_value"}
```

Kinds: `readback_lag` (serve values as of now−N s, from device history),
`readback_lie` (`scale`/`offset`, optionally scoped by `quantities`),
`stuck_value` (freeze at arm time). Defaults OFF (`configs/twin-default.toml`).
These feed the tuner fault-injection suite (WS3/WS4).

## Device semantics (mirrored from the HAL sources)

### PMBus PSU — 0x58 (alt 0x59) — `dcentrald-hal/src/pmbus.rs`

Read commands (SMBus word/block, LE words): `OPERATION` 0x01 (byte; last
written value, 0x80=on), `VOUT_MODE` 0x20 (byte; 5-bit two's-complement
exponent, default −9), `STATUS_WORD` 0x79 (off ⇒ bit 3 `PSU_STATUS_OFF`),
`READ_VIN` 0x88, `READ_IIN` 0x89, `READ_VOUT` 0x8B (ULINEAR16 ÷ VOUT_MODE
exponent), `READ_IOUT` 0x8C, `READ_TEMPERATURE_1` 0x8D,
`READ_FAN_SPEED_1` 0x90, `READ_POUT` 0x96, `READ_PIN` 0x97 (SLINEAR11),
`MFR_ID` 0x99 / `MFR_MODEL` 0x9A / `MFR_REVISION` 0x9B (blocks; the twin
identifies itself as EMU-TWIN/APW-TWIN — no vendor impersonation). SLINEAR11
= signed 11-bit mantissa + signed 5-bit exponent; the encoder picks the
highest-precision representable pair. With OPERATION off, VOUT/IOUT/POUT
collapse to ~1% of truth (rail decay), VIN/PIN keep reporting. Writes other
than OPERATION are refused (`unsupported`) — the production pmbus layer is
read-only telemetry and the twin keeps that shape.

### APW12 SMBus PSU — 0x10 — `dcentrald-hal/src/psu_apw12_smbus.rs`

Opcode-as-register protocol (write opcode, write-read response). POWER_OFF
0x00 / POWER_ON 0x01 (no payload), SET_VOLTAGE 0x02 (payload mV LE, max
1600 mV), READ_VOLTAGE 0x03 (mV LE), GET_FW_VERSION 0x04 → `0x0103` LE,
READ_TELEMETRY 0x05 → 32-byte block (mV, V×10, A×10, W×10, °C×10, power
flag), ENABLE_WDOG 0x06 / DISABLE_WDOG 0x07, GET_HW_VERSION 0x08,
CALIB_STATUS 0x09 → 0x01 ready, GET_AC_POWER 0x0A, READ_ERROR_CODE 0x0B,
READ_ERROR_DATA 0x0C, GET_UPDATE_TIME 0x0D, GET_RESET_CAUSE 0x0E,
CLEAR_FAULTS 0x0F, GET_POWER_SN 0x10.

### EMC2305-class fan controller — 0x2F — CLASS model

**Class-level semantics, not a bit-exact EMC2305 register map** (bit-exact
conformance is a later PoC against the Microchip datasheet; anchors verified:
PWM setting registers and 2-pulses-per-rev tach math). Registers: `0x40+i` =
fan i PWM duty byte (write accepted; 0..255), `0x30+2*i` = fan i tach count
(16-bit BE). Tach count = `rpm ÷ 60 × PULSES_PER_REV (2) × tach_window_s` —
the same 2-pulses/rev law as `dcentrald-hal/src/platform/amlogic/mod.rs`
(`PULSES_PER_REV = 2`, `rpm = edges × 60 / window / 2`). RPM model:
`max_rpm × duty ÷ 255` (duty 0 ⇒ 0 rpm) unless the host physics pushes an
explicit `rpm_i` measurement. Zynq fans are NOT I2C (FPGA `fan-control` IP —
a2 §C.2); this device covers I2C-attached fan controllers only.

### LM75/TMP75 — 0x48..0x4F — `dcentrald-hal/src/i2c.rs`

Pointer registers: 0x00 temperature (16-bit **big-endian** signed, 1/256 °C),
0x01 config, 0x02 THYST (default 75 °C), 0x03 TOS (default 80 °C). TOS/THYST
writes accepted; temperature is driven by the thermal model via `set_values`.

### AT24 EEPROM — 0x50..0x57 — G1 write-denylist semantics

256-byte page per address; offset 0 carries the BHB-class preamble (0x04 by
default). Reads succeed at any offset/length. **Every write returns
`denied`** and counts in `stats.eeprom_write_denied`. The am2 denylist policy
is per-platform (S9/S19 Pro/S21 register none — their 0x55..0x57 are PICs);
the sidecar models the DEVICE side only and refuses all 0x50..0x57 writes so
the twin can assert the daemon-side gate actually engages.

### dsPIC framed — 0x20..0x22 — presence stub

Frames: `55 AA 17` GET_VERSION → `AA 55 <fw>`; `55 AA 04 15 01` ENABLE →
`AA 55 01` (records enabled); `55 AA 04 16 00` HEARTBEAT → `AA 55 01`
(counts). Response bytes beyond these acks are a **presence stub** — exact
frame truth lands with the wire module / held-capture PoC. fw is selectable
via `set_fw` (0x89 default, 0x86 for the G2 refusal scenario).

## Built-in chain protocol (companion, harness-owned)

`harness/scenario_run.py` documents the built-in chain stub TCP protocol
(length-prefixed JSON job dispatch → share response) used for host-side
scenarios until I1's `chain_server` signatures freeze.

## Honesty labels

Evidence produced through this sidecar is `t1-host-scenario` until the guest
attachment PoC ships; no I2C-dependent claim may be labeled T2 (plan.md §11
C1-F1).

---

**Support the DCENT_OS open-source effort:** <https://d-central.tech/fund/>
