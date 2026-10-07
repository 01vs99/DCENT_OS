# BitAxe Hex Supra (board 702) — MAC 30:ED:A0:AF:21:A0

Flashed from stock AxeOS to DCENT_axe v0.3.0 (`bitaxe-hex-supra`) on 2026-09-03.

## Stock backup (restore path)

- `stock-full-16mb.bin` — full 16 MB flash read before any write.
  SHA-256 in `stock-full-16mb.bin.sha256`.
- `stock-nvs.bin` / `stock-nvs-dump.txt` / `stock-nvs-extracted.json` — the stock
  NVS partition (0x9000, 0x6000) and its decoded contents.
- `stock-partition-table.bin` — stock table, identical to repo `partitions.csv`
  except the repo adds a `coredump` region at 0x800000.

Full restore: `esptool --port COM3 write-flash 0x0 stock-full-16mb.bin`

## What was flashed

| Offset | Image | SHA-256 |
| --- | --- | --- |
| 0x0 | `dcentaxe-bitaxe-hex-supra-0.3.0-factory.bin` | `33dac601…683ef1` |
| 0x9000 | `new-nvs.bin` (regenerated) | see `new-nvs.csv` |

Both writes were hash-verified by esptool.

## NVS handling

The factory image fills 0x9000-0xEFFF with 0xFF, so NVS was regenerated rather
than preserved in place. `extract_nvs.py` reconstructs every live key from the
stock dump; `make_nvs.py` re-emits them with only `wifi_ssid` / `wifi_password`
changed, in both the `main` (AxeOS) namespace and the `dcentaxe:config` blob.
Preserved verbatim: pool + fallback pool, 525 MHz / 1220 mV / fan 70%, board
identity (`boardversion=702`, `devicemodel=suprahex`, `asicmodel=BM1368`), and
the DCENT_axe stats blobs (best diff 109,711,166.63, 15 achievements,
best streak 636, lifetime shares 4200, best nonce 0xA6CAE052).

`live-nvs.bin` is a post-boot read-back.

## Known state after flash

Mining is refused fail-closed: `requires_fan_tach` is unconditional for
`is_hex` boards and fan 1 reports 0 RPM (EMC2302 TACH1 count saturated at
0x1FFF) while fan 2 reports ~1650 RPM. This is a hardware condition, not a
flash fault. Do not clear it with `unsafe_lab_safety_bypass`.

---

## 2026-09-03 follow-up: single-fan support (XPSAFE-8)

This unit runs ONE fan, on EMC2302 header 2. The Hex family required tach from
BOTH headers before energizing, so it could never mine on DCENT_axe.

`FanPopulation` (`Both` / `Fan1Only` / `Fan2Only`) now lets the operator declare
which headers are fitted. `requires_fan_tach` is UNCHANGED — a Hex still must
prove a tachometer — so the pinned
`mandatory_tach_set_is_exactly_the_declared_boards` set did not move. What
changed is only WHICH fans the proof is demanded from.

Set on this unit via the config blob (`"fans_populated":"fan2_only"`) and
readable/writable at runtime on `/api/system` (`fansPopulated`). An unknown
value is rejected with HTTP 400 rather than silently defaulting.

Live result: gate passes, rail energizes (1215 mV, ~20 A, ~100 W, VIN 12.3 V),
all 6 BM1368 enumerate, Stratum authorizes against solo.ckpool.org.

## RESOLVED: TPS546 CML false kill (XPSAFE-11 / XPSAFE-12)

Mining used to stop ~17 s into every run:

    STATUS_WORD=0x0202  CML=0x40  (invalid or unsupported data received)
    VOUT_CMD=3.660V READ_VOUT=3.646V READ_VIN=11.72V READ_IOUT=20.3A READ_TEMP=51C
    POWER FAULT ... disabling ASIC for safety

The rail was electrically healthy every time. TWO independent sources set that
flag, and both had to be fixed.

### Cause 1 — the diagnostic I2C bus scan poked the regulator (the actual kill)

`I2cBus::probe` is a ZERO-BYTE write. That is a fine presence test for an EEPROM
or a fan controller, but to a PMBus part a write carrying no command byte is
malformed, and the TPS546 records it as `STATUS_CML = 0x40`. The scan sweeps
0x08..0x77, which includes the regulator at 0x24, and it runs AFTER
`PowerManager::new` — so it re-dirtied a status word that init had just cleared.
Seventeen seconds later the supervisor's first fault check read it and executed
the unconditional hard-kill, while the board was mining and submitting accepted
shares.

Fixed by clearing the regulator's fault latch immediately after the scan, in the
code that caused it. The hard-kill itself is untouched and still unconditional;
a CML seen from then on was raised by something other than our own bus scan.

### Cause 2 — four protection limits are computed in the wrong domain

`configure_limits` runs after `CLEAR_FAULTS`, so any write the part refuses
latches CML too. Four writes are refused on EVERY boot:

| Register | Driver wants | Register actually holds |
| --- | --- | --- |
| VOUT_OV_FAULT | 4.500 V | 1.148 V |
| VOUT_OV_WARN | 4.176 V | 1.090 V |
| VOUT_UV_WARN | 3.240 V | 0.910 V |
| VOUT_UV_FAULT | 2.700 V | 0.850 V |

Proven by probe, not inferred: reading each register and writing back its OWN
value SUCCEEDS, so the registers are writable and it is the value that is
refused. `VOUT_COMMAND`, `VOUT_MIN`/`MAX` and both `VOUT_MARGIN` registers all
accept rail-domain values, so the four PROTECTION limits are evidently scaled
differently on a three-series-domain board.

STILL OPEN: the correct scaling needs the TPS546D24A datasheet. Writing a
guessed threshold to a last-line protection register on a 100 W rail is not
something to settle by trial. Until then those four keep the part's own
defaults — the same state every Hex Supra has always run in, including under
stock AxeOS, whose upstream ESP-Miner values these are. Each refusal now logs
the value wanted, the value actually in force, and the IC's STATUS_CML byte.

### Three hypotheses tested on hardware and falsified

1. Regulator power-on timing. A 150 ms settle between the enable GPIO and PMBus
   configuration changed nothing. Reverted.
2. `VOUT_COMMAND` ordering. Seeding the output command before the limits
   changed nothing.
3. `VOUT_SCALE_LOOP` ordering. Moving it ahead of the VOUT registers changed
   nothing. Kept anyway — writing the feedback scale before the registers it
   governs is correct regardless.

A bounded retry with the inter-command delay was added at the same time; the old
error path skipped the delay entirely, so one NACK cascaded into the next. That
retry alone fixed `IOUT_OC_FAULT_RESP`, which was genuinely transient.
`VIN_OV_FAULT_RESP` (value 0xB7) is still refused and is unexplained.

### Result

    hashrate 2.43 TH/s   110 W   52 C   18 shares accepted   0 rejected
    6x BM1368 @ 525 MHz, 1215 mV, no power fault

---

## 2026-09-03 soak: 2h35m clean, then a site power loss (NOT a firmware fault)

`soak-20260903.csv`, 232 samples at one minute: **153 good, then 79 unreachable.**

| | |
| --- | --- |
| Clean run | 02:18:33 -> 04:53:05 (2h35m) |
| Hashrate | mean **3.89 TH/s**, peak **5.34** (rated ~3.7) |
| Power | ~111 W, ~29-31 J/TH |
| ASIC temp | 53-60 C · regulator 82-90 C |
| Shares | **2234 accepted / 1 rejected** |
| Fan | ONE fan, header 2, declared `fan2_only` |

**The unit did not fail.** One second before the last good sample it was at 4.50 TH/s, 82.75 C. The
cause is a mains loss at the bench site, evidenced by a Windows `Kernel-Power` *"Power source change"*
event at **04:53:54** — between the last good poll (04:53:05) and the first failure (04:54:06) — after
which the workstation ran on battery. The ESP32 vanished from USB entirely: no COM port and **no
`VID_303A` device enumerated at all**, which means unpowered rather than crashed or hung. Two further
power-source changes followed at 07:51 and 08:16, so the supply was unstable rather than cleanly
restored.

No action is needed on the unit. It is flashed, its configuration is in NVS, and it rejoins the network
by itself when the supply returns.

**A telemetry defect this soak caught, worth a firmware lane:** at ~t+120 min the dashboard's headline
hashrate collapsed from 4.2 TH/s to 0.14 while the miner was working normally — power steady at 111.7 W
and 23.8 A, pool connected and authorized, accepted shares advancing four in ten seconds. The cause is in
`/api/pools` `recent_events`: the disclosed 2 % donation window switches pools and takes a difficulty
change, and the rolling windows are share-derived, so they empty and the headline reads near zero for
minutes. The donation works as designed; the most prominent number on the dashboard saying the miner has
stopped when it has not is the defect.
