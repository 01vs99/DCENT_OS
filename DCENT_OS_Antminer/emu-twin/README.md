# DCENT_OS emu-twin — BM13xx hashboard-chain emulator (I1)

A host-side BM1362 hashboard-chain emulator that **really mines**: one TCP
port per chain, N simulated chips speaking the byte-true BM13xx serial wire
protocol, with a genuine double-SHA256 nonce search behind every returned
share, physics-driven per-chip temperature/power, and a sigmoid HW-error
cliff. This is the first piece (implementer I1) of the DCENT_OS emulation
twin described in

(layer 2 of the four-layer twin).

## What is here

| File | Role |
|---|---|
| `protocol.py` | Wire framing/CRCs/constants — byte-true mirror of `dcentrald-asic/src/protocol.rs` + the BM1362 builders (`dcentrald-asic/src/bm1362/mod.rs`) and response parsers (`bm1362/assigned_address.rs`, `bm1362/uart_transport.rs`) |
| `nonce_engine.py` | REAL double-SHA256 nonce search (stdlib `hashlib`), midstate-accelerated via sha256-object `.copy`; optional `concurrent.futures` process pool; bounded, subsampled windows |
| `physics.py` | Per-chip power model `P = c_eff·V²·f + P_static(T)`, per-board thermal RC network (die → board → airflow → ambient, fan-affinity `h ∝ PWM^0.9`, sensor lag), sigmoid HW-error cliff `1/(1+e^{-k(f-f_cliff(T))})` with per-chip bins |
| `chain_server.py` | TCP server (one chain per port, loopback-only by policy): chip roster/admission, register file, job dispatch, nonce responses, HW-error injection, physics ticker |
| `tests/` | pytest suite (framing vs protocol.rs constants, CRC vectors, full mini mining loop, physics sanity, G-invariant no-device checks) |

## Run

Windows Git Bash, `py -3` (3.12), **stdlib only**, no pip installs:

```bash
cd DCENT_OS_Antminer/emu-twin
py -3 -m pytest tests/ -q          # test suite
py -3 chain_server.py --chips 8 --port 40260 --difficulty 0.001
```

One process per chain (a 3-board unit = three ports). The server prints a
status line with physics-derived temperature/power/error rates.

## Interface contract (for the daemon-side twin owner)

**Transport**: TCP, one chain per port, loopback by default (`--host` is
policy-restricted to loopback). The daemon side connects QEMU character
devices (`-serial tcp:...`) or a test client to this socket; bytes are the
wire bytes below (the UART itself is absent, so baud is logical only).

**Host → chain (CMD frames)** `[55 AA][hdr][len][payload][CRC5]`:

| Frame | Bytes (post-preamble) | Effect |
|---|---|---|
| ChainInactive | `53 05 00 00 CRC5` | all chips forget addresses |
| SetChipAddress | `40 05 ADDR 00 CRC5` | first un-addressed chip claims ADDR (stride 2) |
| GetAddress (bcast read reg 0) | `52 05 00 00 CRC5` | every assigned chip answers, chain order |
| single read | `42 05 CHIP REG CRC5` | addressee answers |
| bcast write | `51 09 00 REG VAL_BE[4] CRC5` | register write, all chips |
| single write | `41 09 CHIP REG VAL_BE[4] CRC5` | register write, one chip |
| **JOB frame** | `[55 AA] 21 56 [82-byte payload] [CRC16 BE]` (88 B total) | real nonce search starts |

CMD CRC5 = poly `0x05`, init `0x1F`, MSB-first. Job CRC16 = CCITT-FALSE
poly `0x1021` init `0xFFFF` over bytes `[2:86]`, appended big-endian.
Length-byte note: the proven BM1362 builder writes `0x56`; the S19k Track-1
bosminer packer writes `0x36` for the same 88-byte frame — **both are
accepted**; unknown length bytes are refused.

**Job payload (82 B)**: `job_id(1) num_midstates=0x01(1) starting_nonce(4)
nbits(4 LE) ntime(4 LE) merkle_root(32, 32-bit-word-reversed)
prev_block_hash(32, word-reversed) version(4 LE)` — the full-header
`UartFullHeader` transport that `asic_protocol_spec.rs` selects for
BM1362/66/68/70 (the chip computes its own midstates, so there is no
midstate dispatch on this wire).

**Chain → host (responses)** — 11 bytes: `[AA 55][value/reg-specific 8
bytes][trailer]`, trailer bits 4:0 = response CRC5 (modified state machine,
init `0x03`), bit 7 = job-response marker. Register read layout is pinned by
`assigned_address.rs` (`value BE(4) | responder_addr | reg | 00 00`).
Nonce response: `nonce LE(4) | midstate_idx | result | vbits BE(2) | flags`,
where `result` high nibble carries job-id bits `[6:3]` (echo
`(result & 0xF0) >> 1`; dispatch steps by `JOB_ID_INCREMENT = 24`), low
nibble = small core; `flags = 0x80 | CRC5`.

**Configuration**: `--chips`, `--difficulty` (fractional OK — the twin
mines a LOW target for found-share rate, not terahash), `--rail-v`, `--pwm`,
`--search-fraction`, `--max-nonces` (per-chip per-job window), per-chip bins
(`physics.ChipBin`, k / f_cliff25 / thermal derate). Rail volts are
server-side config (`SimChain.set_rail`); no wire register claims rail
volts, and none was invented.

## Tier honesty (read before citing numbers)

**T1 sim / T2 twin evidence only; model outputs, not silicon truth.**

- Nonces are REAL (every returned share passes an independent sha256d
  recompute — see `tests/test_chain_server.py`), but hashrate is NOT: the
  Python search rate is irrelevant and must never be reported as hashrate.
- Temperature, power, J/TH, and error rates come from `physics.py` models
  calibrated on provenance-labeled anchors ([LUXOS-79-LIVE] rows mirrored
  from `dcentrald-silicon-profiles/src/operating_points.rs`, [A2-TWIN-SPEC]
  thermal anchors, [BRAINS-AUTOTUNE] PLL spread, [DCENT-MODEL] simulation
  knobs). Residuals vs every anchor row are printable via
  `physics.calibration_residuals` and pinned in the tests.
- Calibration fit: the step-0 nameplate row reproduces exactly (it is the
  calibration anchor); other rows sit within a documented ±20 % band — the
  two-point model's honesty band, not measurement error.

## Oracle-class / fixture policy

- Byte-truth is pinned ONLY against in-tree oracle fixtures
  ([DCENT-in-tree], citing the Rust file/test each vector came from: the
  retained response-CRC5 contract vectors in `protocol.rs`, the pinned
  frame-builder bytes in `bm1362/mod.rs`, the response geometry in
  `asic_protocol_spec.rs`). No new vectors were invented where retained ones
  exist; where none exist, tests compute expected values from independent
  local implementations (cross-consistency) or hand-derived known answers,
  labeled as such.
- Data tables from held corpora appear ONLY as provenance-labeled constants
  (e.g. the [LUXOS-79-LIVE] anchor rows in `physics.py`, carrying their
  source citation). No copied code, no unlabeled magic numbers.
- Known inference (flagged, not hidden): the generic register-read response
  layout for `reg != 0x00` extends the pinned reg-0 layout
  (`value BE(4)|addr|reg|00 00`); only reg-0 parsing is pinned by in-tree
  tests. The nonce-frame trailer CRC5 is computed with the command init
  `0x03` for cross-consistency — the proven daemon path does not validate
  that trailer (TicketMask gates returns), and the RTL's distinct
  job-response init (`0x1B`) is explicitly NOT claimed as covered.

## Safety

No live hardware, no SSH, no device files: the server binds TCP only
(loopback by policy), every filesystem path goes through a device-namespace
guard (`chain_server._guard_path`), and a test runs a full session with
`open` patched to explode on `/dev/*`-style paths (G-invariant spirit).

## Scope limits / open issues

- Serial-UART routes only (BM1362-class full-header dispatch). FPGA FIFO
  midstate transport (BM1387/BM139x) is parsed on the constants level but
  not dispatched — Phase 4 territory per A2.
- The UART relay register (`0x2C`), core register indirect access (`0x3C`),
  and analog-mux temperature readout are modeled as passive register
  storage; no chip-side behaviors are claimed for them yet.
- Broadcast fan-out serialization delay (µs-scale per-chip delay) is not
  implemented; responses return promptly in chip order.
- The stratum stub + QEMU guest plumbing belong to other twin owners.

## Fund / Support

DCENT open-source projects are funded by the community:
**[https://d-central.tech/fund/](https://d-central.tech/fund/)** (Stripe +
BTCPay). A missing fund link is a release-gate failure — never strip it.

License: GPL-3.0 (DCENT_OS emu-twin). Company: D-Central Technologies
(https://d-central.tech/).
