#!/usr/bin/env python3
"""no-orphan-driver gate: fail when a pub PSU/regulator/PIC backend is unreachable.

Hardware-enablement constitution rank 36 (H4 #7), shipped 2026-08-03 (W8-B).

The recurring failure this prevents: a complete `pub` PSU/regulator/PIC backend
compiles, is unit-tested, and ships while having ZERO non-test construction
sites -- i.e. it is unreachable in production. `Apw12SmbusBackend` (~1,200
lines) and `Apw12PlusBackend` (~500 lines) both shipped that way; so did the
`PsuBackend` factory enum, `Pic1704Service`, and `PicController::flash_firmware`.
This is the type-level sibling of the memory rule
 (tests that
construct a backend directly cannot see that production never does).

What this gate checks, per `pub` struct/enum defined in the SCOPED power/PIC
modules:

1. TYPE CHECK -- construction-shaped evidence (`Type::assoc_fn(..)`,
   `Type::Variant(..)`, or a `Type { .. }` literal) must exist in at least one
   PRODUCTION position: not inside a `#[cfg(test)]` region, not in a `tests/`,
   `benches/`, or `examples/` tree, and not inside the type's own inherent
   `impl` block (self-construction inside an uncalled factory proves nothing).
2. METHOD CHECK -- for types that PASS the type check (live types), every
   `pub fn` in a production inherent-impl region must have at least one
   call-shaped use (`.name(` or `::name(`) somewhere in the workspace,
   test or production. Zero-anywhere = an orphan capability on a live type
   (the `flash_firmware` class).

3. SCOPE CHECK -- every entry in SCOPE_GLOBS must match at least one file.
   A scope entry that silently matches nothing is the same failure class this
   gate exists to catch, occurring inside the gate itself. Round-16 B6 found
   exactly that: `dcentrald-hal/src/voltage_rail_adapters.rs` had been listed
   as scope since 2026-08-03 while the real file lives in `dcentrald-asic/`,
   so two complete `pub` VoltageRail energization adapters (`DsPicVoltageRail`,
   `Pic1704VoltageRail`) were never scanned. A dead glob is now a FAIL.
4. REASON CHECK -- every TOLERATED_ORPHANS value must be a dated, substantive
   reason. An allowlist without reasons is what a future "generalisation" wave
   strips without noticing; blanking a reason must fail loudly, not pass.

Known limitations (deliberate; documented so nobody "fixes" them into noise):
- One-hop only. A production construction inside a function that is itself
  unreachable still passes (e.g. `psus.rs`'s catalog gained a production
  consumer in rank-35 `power_topology.rs` whose own consumers are test-only).
  Transitive reachability is the compiler's job, not a regex gate's; the
  allowlist ledger is where such chains are recorded.
- Method-name collisions across types. The METHOD CHECK matches `.name(` /
  `::name(` textually, so a method is treated as live when a DIFFERENT type's
  identically-named method is called. Live example: the daemon calls
  `CurtailmentController::enter_sleep`, which masks the fact that
  `ThermalController::enter_sleep` has no production caller either. Resolving
  this needs type resolution, not regex; where it matters, the allowlist row
  for the visible half records the masked half explicitly.
- Construction-shaped only. A type whose values are minted exclusively by
  derive-generated conversions (`thiserror` `#[from]`, `Into`, `?`) shows zero
  constructions. Such rows are adjudicated by reading the crate, not by
  loosening the regex.
- Scoped to `DCENT_OS_Antminer/dcentrald/`. The three 2026-07-30 ESP
  rail-enablement cases lived in `DCENT_OS_ESP/` and would need a
  sibling instance of this gate there.

Existing orphans are pinned in TOLERATED_ORPHANS below -- explicit, dated,
reasoned. The gate FAILS on any NEW orphan and also FAILS when an allowlist
entry stops being an orphan (stale ledger rows must be deleted in the same
change that wires the backend). NEVER silently exempt.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Scope: the power / regulator / PIC backend modules.
# ---------------------------------------------------------------------------

SCOPE_GLOBS = (
    "dcentrald/dcentrald-hal/src/psu*.rs",
    # 2026-08-07 (Round-16 B6): corrected from `dcentrald-hal/src/`, which had
    # matched ZERO files since the gate shipped. See SCOPE CHECK above.
    "dcentrald/dcentrald-asic/src/voltage_rail_adapters.rs",
    "dcentrald/dcentrald-asic/src/pic/*.rs",
    "dcentrald/dcentrald-asic/src/pic1704/*.rs",
    "dcentrald/dcentrald-asic/src/dspic/*.rs",
    # 2026-08-07 (Round-16 B6): thermal actuation is a safety-critical control
    # surface in the same "complete pub backend, zero production constructions"
    # class as the PSU drivers. 36 of its 38 pub types are live; the residue is
    # adjudicated individually in TOLERATED_ORPHANS below.
    "dcentrald/dcentrald-thermal/src/*.rs",
)

# Method names never reported by the method check: constructor-shaped names are
# covered by the type check, and these trait-flavored names have call sites the
# textual scan cannot attribute reliably.
METHOD_NAME_SKIP = {"new", "default", "clone", "fmt", "drop", "open"}

# ---------------------------------------------------------------------------
# The pinned orphan ledger (rank-36 census, verified 2026-08-03 by W8-B).
# Every row is an existing, deliberate, VISIBLE debt. Removing a row is only
# legal in the same change that gives the backend a production caller (or
# deletes it). Adding a row requires the same adjudication this census got.
# ---------------------------------------------------------------------------

TOLERATED_ORPHANS = {
    # ======================================================================
    # Rank-36 census, adjudicated 2026-08-03 (W8-B). H4 #7 predicted "6";
    # the verified set at gate semantics is 13 orphan types + 12 orphan
    # methods. One H4 item (the psus.rs catalog) is NOT here: rank-35
    # power_topology.rs gave it a production consumer, so it no longer
    # trips the one-hop construction check (its chain is still test-
    # terminated -- tracked in the rank-36 deliverable, not this ledger).
    # ======================================================================
    #
    # -- complete PSU drivers with zero production constructions ------------
    "Apw12SmbusBackend": (
        "2026-08-03: complete APW12 SMBus driver (CV1835/AM335x/AML, "
        "psu_apw12_smbus.rs:380); all 16 constructions are #[cfg(test)]. "
        "Historical would-be orchestrators (retired cvitek_cold_boot.rs:523, "
        "beaglebone_cold_boot.rs:392) were production-unreachable in that audit; CV runtime and markers retired in L17. "
        "Wiring = H4 G-PSU2, a rail-energization change gated separately."
    ),
    "S21DiscoverOnlyRail": (
        "2026-09-15: L14 S21-family PSU discovery profile "
        "(voltage_rail_adapters.rs:384) — DELIBERATELY production-unwired: "
        "the reviewed design is passive discover-only bench cards "
        "(dcentrald-asic/examples/s21_psu_discover.rs; no bus probe, no "
        "PSU command, no fan write). SUPPORT_MATRIX.md S21-class ceiling "
        "section records external-DAC as unsupported. Wiring becomes "
        "legitimate only with a physical PSU protocol law (T21/S21+ stay "
        "undriven; no sibling polarity inherited)."
    ),
    "Apw12PlusBackend": (
        "2026-08-03: complete APW12+ register driver (S21 family, "
        "psu_apw12_plus.rs:490); all 6 constructions are #[cfg(test)]. Live "
        "S21 path energizes via GPIO 437 only (amlogic/mod.rs). Wiring = H4 "
        "G-PSU3, BLOCKED by the unresolved gpio437 polarity item (Tier D)."
    ),
    "PsuBackend": (
        "2026-08-03: factory enum psu.rs:3720; open_apw12_framed/"
        "open_apw12_service/open_legacy have zero call sites anywhere "
        "(not even tests). Kept as the intended dispatch seam until the "
        "rank-35 PowerTopology descriptor takes over dispatch (H4 #10)."
    ),
    "I2cServiceApwBus": (
        "2026-08-03: shared-I2C-service variant of the APW UART-tunnel bus "
        "(psu_apw_uart_tunnel.rs:360); zero constructions anywhere, only doc "
        "references and a re-export. The live .79 path deliberately uses the "
        "raw bit-bang variant instead (am3_bb_mining.rs:764-772 documents "
        "why). Kept for the single-I2C-owner migration."
    ),
    # -- PIC1704 runtime controller ----------------------------------------
    "Pic1704Service": (
        "2026-08-03: CV1835 PIC1704 controller (pic1704/service.rs:188); "
        "zero constructions anywhere, even tests (programmer.rs:554 notes a "
        "real one cannot be built without hardware). Only would-be callers "
        "were historical commented blocks in beaglebone.rs:1394 and now-retired cvitek.rs:362; CV markers are now test-only. "
        "Programmer variants are recovery-tool-gated by design."
    ),
    # -- DELIBERATE fail-closed recovery tokens (do NOT wire) ---------------
    "ConfirmedBrickedToken": (
        "2026-08-03: operator-confirmation token (pic1704/programmer.rs:122);"
        " 21 test constructions, zero production. DELIBERATE: the 2026-04-29 "
        "corruption-prevention purge removed every production mint (pic-"
        "recovery/src no longer references it). Unmintable-in-production is "
        "the safety property; wiring it would be a regression, not a fix."
    ),
    "AcknowledgeSixtyPercentConfidence": (
        "2026-08-03: fw86-recovery confidence token "
        "(dspic/recovery_fw86.rs:260); 13 test constructions, zero "
        "production. Same deliberate class as ConfirmedBrickedToken: the "
        "fw86 reflash executor has no shipped production caller by the "
        "corruption-prevention guarantees."
    ),
    # -- desk-RE decode capability never wired ------------------------------
    "S9FactoryBadCore": (
        "2026-08-03: BADCORE flash-table decoder (pic/mod.rs:107); parse() "
        "called only from its own test module. Reading it live requires a "
        "bootloader-mode PIC, which production deliberately avoids. Unwired "
        "AMTC-jig RE loot; keep or delete, but do not wire casually."
    ),
    "S9FactoryFreq": (
        "2026-08-03: FREQ silicon-binning flash-table decoder "
        "(pic/mod.rs:135); same situation as S9FactoryBadCore."
    ),
    # -- superseded / dormant dsPIC seams -----------------------------------
    "RxFrame": (
        "2026-08-03: framed-reply decode/display type (dspic/mod.rs:498); "
        "zero constructions anywhere. The live framed parser path never "
        "adopted it. Candidate for deletion."
    ),
    "DspicEndpointSession": (
        "2026-08-03: dspic/mod.rs:2867. Its own doc (:3000) says new "
        "production routes must use it, but production actually migrated to "
        "ObservedDspicEndpointSession (2026-07-19 checkpoints). Zero "
        "constructions anywhere. Doc/route drift; adjudicate delete-or-"
        "migrate before wiring."
    ),
    "Pic0x89": (
        "2026-08-03: raw fw0x89 wrapper (dspic/mod.rs:5023); superseded by "
        "the service-backed Pic0x89Service in the 2026-04-25 single-I2C-"
        "owner migration. Zero constructions; a stale comment at "
        "s19j_hybrid_mining.rs:11674 still cites it."
    ),
    "Dspic33Ep16Gs202": (
        "2026-08-03: S17 family-alias scaffold (dspic/mod.rs:5546); "
        "deliberately dormant -- no live S17 unit on the fleet and its probe "
        "addresses are marked STILL NEEDS LIVE S17. Zero constructions."
    ),
    # -- orphan pub methods on live types -----------------------------------
    # Several of these are voltage/energization-shaped. Wiring ANY of them is
    # a rail-risk change requiring its own review -- this ledger only makes
    # them countable.
    "PicController::flash_firmware": (
        "2026-08-03: pic/mod.rs:778; the S9 BraiinsOS PIC-reflash capability "
        "is present-but-unreachable (H4 SS1b): zero call-shaped references "
        "workspace-wide. Physical ICSP remains the deterministic recovery "
        "path per the corruption-prevention guarantees; do NOT wire this to "
        "make the gate pass."
    ),
    "PicController::get_voltage_pic": (
        "2026-08-03: pic/mod.rs:557; cached-DAC getter, zero callers."
    ),
    "PicController::voltage_to_pic": (
        "2026-08-03: pic/mod.rs:571; volts->DAC encode helper, zero callers "
        "(production encodes via dcentrald_common::pic16_mv_to_dac)."
    ),
    "PsuController::set_voltage_v": (
        "2026-08-03: psu.rs:193; volts-flavored setter, zero callers "
        "(production path uses set_voltage at psu.rs:2542)."
    ),
    # 2026-09-10: read_status_0x03 removed from the zero-anywhere method
    # ledger: raw_status_requires_complete_word_even_with_valid_frame_checksum
    # now calls it in tests. This is raw-word/length coverage, not a
    # production consumer, voltage interpretation, or readiness claim.
    "DspicController::from_endpoint": (
        "2026-08-03: dspic/mod.rs:1476; endpoint-session constructor path "
        "with zero callers (production constructs via services)."
    ),
    "DspicController::probe_addresses": (
        "2026-08-03: dspic/mod.rs:1617; address-probe helper, zero callers."
    ),
    "DspicController::ramp_voltage": (
        "2026-08-03: dspic/mod.rs:2460; voltage-ramp capability, zero "
        "callers. Energization-shaped -- never wire without its own review."
    ),
    "DspicService::from_endpoint": (
        "2026-08-03: dspic/mod.rs:2978; endpoint-session constructor path "
        "with zero callers (see DspicEndpointSession row)."
    ),
    "DspicService::cold_boot_init_with_options_cancellable": (
        "2026-08-03: dspic/mod.rs:3361; cancellable cold-boot variant, zero "
        "callers. Energization-shaped -- never wire without its own review."
    ),
    "PicVariant::is_framed": (
        "2026-08-03: dspic/mod.rs:4970; predicate with zero callers."
    ),
    "Pic0x89EndpointSession::into_controller": (
        "2026-08-03: dspic/mod.rs:5195; conversion into the orphaned raw "
        "Pic0x89 wrapper (see its row); zero callers."
    ),
    # ======================================================================
    # Round-16 B6 census, adjudicated 2026-08-07. Two sources:
    #   (a) the SCOPE_GLOBS dead-glob fix, which finally scanned
    #       dcentrald-asic/src/voltage_rail_adapters.rs for the first time;
    #   (b) the dcentrald-thermal/src widening (Round-15 A7's open item).
    # Each row below was adjudicated individually against a COMPLETE,
    # untruncated scan of all 2,618 `.rs` files under `projects/` (no
    # `head`/`tail`/limit anywhere), cross-checked against the gate's own
    # census. Round 15 retracted an orphan claim produced by a truncated
    # `git grep | head -8`; an orphan gate is the one place where a truncated
    # search MANUFACTURES the finding it reports.
    # ======================================================================
    #
    # -- energization-shaped VoltageRail adapters (dead-glob discovery) -----
    # These are the Apw12SmbusBackend class exactly: complete `pub` drivers
    # with live set_mv/enable/disable, zero production constructions. They
    # went unseen for four days because the scope entry naming their file
    # pointed at the wrong crate. Wiring EITHER is a rail-risk change that
    # needs its own review -- this ledger only makes them countable.
    "DsPicVoltageRail": (
        "2026-08-07: generic dsPIC33EP VoltageRail adapter "
        "(dcentrald-asic/src/voltage_rail_adapters.rs:61); zero constructions "
        "anywhere, production or test. The live AM2 path deliberately uses the "
        "observed-firmware Pic0x89VoltageRail instead "
        "(s19j_hybrid_mining.rs:1183). Kept because the structural contract "
        "`asic_voltage_rail_adapters_module_exists_and_uses_policy` "
        "(dcentrald-common/src/voltage_rail.rs:1402-1421) pins "
        "`impl VoltageRail for DsPicVoltageRail` as required source: deleting "
        "the type breaks that pin. Energization-shaped -- never wire casually."
    ),
    "Pic1704VoltageRail": (
        "2026-08-07: PIC1704 VoltageRail adapter "
        "(dcentrald-asic/src/voltage_rail_adapters.rs:299); zero constructions "
        "anywhere. NECESSARILY orphaned: its only constructor takes "
        "`&mut Pic1704Service`, and Pic1704Service is itself a pinned orphan "
        "in this same ledger with zero constructions even in tests. It cannot "
        "become live before Pic1704Service does. Same structural-contract pin "
        "as the DsPicVoltageRail row (voltage_rail.rs:1412)."
    ),
    # -- deliberate, truth-contract-load-bearing non-instantiation ----------
    "HeaterController": (
        "2026-08-07: space-heater room-temp PID "
        "(dcentrald-thermal/src/heater.rs:80); 2 constructions, both in its "
        "own #[cfg(test)] module. DELIBERATE and LOAD-BEARING: "
        "dcentrald-api/src/rest.rs:2798-2814 advertises "
        "`target_temp_control: false` BECAUSE this controller is not "
        "instantiated and no room-temp setpoint endpoint exists, and it "
        "explicitly forbids flipping that capability true without first "
        "wiring a live closed-loop controller AND a setpoint endpoint AND "
        "preserving the PWM<=30 home cap. Wiring this type is a product + "
        "safety-envelope change, not a lint fix. Do NOT delete: the REST "
        "truth-contract comment cites it by name."
    ),
    # -- genuine orphans: visible debt, adjudicated, NOT silently deleted ---
    "ThermalError": (
        "2026-08-07: crate error enum (dcentrald-thermal/src/lib.rs:53). "
        "Genuine orphan, wider than the gate can see: a complete scan of all "
        "2,618 `.rs` files under projects/ finds NO function in "
        "dcentrald-thermal returning `Result<..>` at all, and NO variant of "
        "ThermalError constructed anywhere. Its only reference outside the "
        "definition is the `#[from]` bridge at dcentrald/src/error.rs:30, "
        "which therefore can never fire. Not a safety gap -- the thermal "
        "safety path signals through ThermalAction / SupervisorAction, not "
        "Result. Deletion is the right end state but must also remove "
        "DaemonError::Thermal, which is outside dcentrald-thermal."
    ),
    "ThermalController::exit_sleep": (
        "2026-08-07: controller.rs:960; zero references anywhere, even tests. "
        "NOT the dangerous asymmetry it looks like: its sibling "
        "ThermalController::enter_sleep (:954) is ALSO production-unreachable "
        "-- every production sleep/wake call site (daemon.rs x7, "
        "dcentrald-api/src/rest/late.rs:10748) targets the identically-named "
        "CurtailmentController::enter_sleep (curtailment.rs:55). The gate "
        "cannot see that because its method check is textual, so the sibling "
        "is masked as live (see the method-name-collision limitation above). "
        "ThermalState::Sleep is never entered in production, so there is no "
        "stuck-asleep hazard. Dormant pair; adjudicate delete-or-wire "
        "together, never one half alone."
    ),
    "ThermalController::is_temp_stale": (
        "2026-08-07: controller.rs:974; zero callers. NOT a safety wiring gap "
        "-- the live update() path already performs this check inline at "
        "controller.rs:564 and :672 against TEMP_STALE_TIMEOUT_S, driving "
        "fans to profile max and requesting EmergencyShutdown. The "
        "2026-03-25 swarm review's recommendation to 'wire is_temp_stale() "
        "into the daemon watchdog loop' is superseded by that inline net. "
        "DRIFT HAZARD, recorded not fixed: this accessor hardcodes the "
        "literal `30` while the live path uses TEMP_STALE_TIMEOUT_S (=30 "
        "today). If the constant ever moves, the public predicate silently "
        "disagrees with the enforced behaviour. Fix = use the constant, or "
        "delete the accessor."
    ),
    "OffGridController::smoothed_voltage": (
        "2026-08-07: offgrid.rs:528; zero callers. Redundant public accessor "
        "-- the underlying field is used 12x inside offgrid.rs and is already "
        "surfaced to consumers through OffGridTelemetry.bus_voltage_v "
        "(offgrid.rs:457, :498), which IS live (daemon.rs:6357). Lowest-risk "
        "row in this batch; safe to delete whenever someone touches the file."
    ),
    "ThermalProfile::s19j_pro_industrial": (
        "2026-08-07: profiles.rs:103; zero references anywhere. NOT an "
        "energization gap: production never calls ANY named ThermalProfile "
        "constructor -- daemon.rs:10498 and serial_mining.rs:8563 both build "
        "the struct literally from TOML config, so the shipped S19j Pro "
        "envelope comes from config, not from here. home_quiet()/hacker() "
        "escape this gate only because tests reference them. REFERENCE-DRIFT "
        "HAZARD, recorded not fixed: this constructor encodes a researched, "
        "sourced envelope (target 60C / hot 80C / dangerous 90C / fan_max 80, "
        "attributed to the Phase-1 Agent-7 probe + bosminer TEMPCTRL) and "
        "NOTHING asserts the shipped am2-s19jpro config defaults match it. "
        "The right fix is a config-vs-constructor pin, not deletion."
    ),
    "SupervisorAction::is_hash_cut": (
        "2026-08-07: supervisor.rs:235; zero callers. Added by Round-15 A3 as "
        "the documentation sibling of is_fan_request(), which IS called by "
        "filter_actions_for_declared_medium (supervisor.rs:267). The comment "
        "at supervisor.rs:2750 only DESCRIBES that is_hash_cut() actions "
        "survive medium filtering; no assertion calls it. Deliberately kept "
        "as a visible orphan rather than silenced: the whole cooling-medium "
        "axis still has zero production consumers (Round-15 A9 F-9), and this "
        "row is the only automated signal of that. Turning the :2750 comment "
        "into an is_hash_cut() assertion is the right fix, and belongs with "
        "the work that gives the axis a real consumer -- not a drive-by that "
        "removes the signal while the axis stays unconsumed."
    ),
    # -- deliberate fail-closed desk-evidence surfaces (2026-08-20) --------
    "Apw9Codec": (
        "2026-08-20: host-only APW9 held-frame codec "
        "(dcentrald-hal/src/psu_apw9.rs:78); all constructions are in its "
        "own tests and LIVE_DISPATCH_AVAILABLE is false. The type has no I2C "
        "handle, its SET method always refuses, and it intentionally ships "
        "unreachable so exact signed-root evidence can be decoded without "
        "minting an APW9 probe, voltage scale, dispatcher, or rail authority."
    ),
    "FailClosedPsuRoute": (
        "2026-08-20: APW8 refusal catalog enum "
        "(dcentrald-hal/src/psu_routing.rs:16); both constructions are in its "
        "own test and there is deliberately no production dispatcher. Its row "
        "leaves address, enable GPIO, opcode, and millivolt units unset and "
        "set_voltage_mv always errors. Wiring it merely to satisfy reachability "
        "would falsely imply a shipped APW8 control route; live wiring requires "
        "separate exact endpoint and electrical evidence."
    ),
}


# ---------------------------------------------------------------------------
# Allowlist reason quality. A dated, substantive reason is the whole value of
# the ledger: it is what stops a future "cleanup" wave from deleting a
# deliberate fail-closed scaffold, and what stops a real orphan from hiding
# behind a bare name. Blanking a reason must FAIL, not silently pass.
# ---------------------------------------------------------------------------

# Floor set to catch BLANK and bare-stub reasons, not to grade prose. The
# terse-but-adequate rows ("2026-08-03: dspic/mod.rs:4970; predicate with zero
# callers.", 59 chars) still pass; "", "TODO", "wired later" and a bare name
# do not. The dated `YYYY-MM-DD: ` prefix is the stronger of the two signals.
ALLOWLIST_REASON_MIN_CHARS = 40
DATED_REASON_RE = re.compile(r"^\s*20\d{2}-\d{2}-\d{2}:\s*\S")


def verify_allowlist_reasons() -> bool:
    ok = True
    for name, reason in TOLERATED_ORPHANS.items():
        if not isinstance(reason, str) or not DATED_REASON_RE.match(reason):
            ok = False
            print(
                f"NO_ORPHAN_POWER_BACKEND_FAIL allowlist row {name!r} has no "
                "dated reason. Every TOLERATED_ORPHANS value must begin "
                "'YYYY-MM-DD: ' and explain WHY the backend must ship "
                "unreachable. A row without a reason cannot be adjudicated by "
                "the next reader and will be deleted by the next cleanup wave "
                "-- which is how a deliberate fail-closed scaffold gets "
                "silently wired or removed.",
                file=sys.stderr,
            )
            continue
        if len(reason.strip()) < ALLOWLIST_REASON_MIN_CHARS:
            ok = False
            print(
                f"NO_ORPHAN_POWER_BACKEND_FAIL allowlist row {name!r} has a "
                f"stub reason ({len(reason.strip())} chars, minimum "
                f"{ALLOWLIST_REASON_MIN_CHARS}). State the evidence: where the "
                "constructions are, why production has none, and what wiring "
                "it would cost.",
                file=sys.stderr,
            )
    return ok


# ---------------------------------------------------------------------------
# Rust source masking: blank out comments and string/char literals while
# preserving byte offsets, so regex/brace logic never fires inside them.
# ---------------------------------------------------------------------------

def mask_rust(text: str) -> str:
    out = list(text)
    i = 0
    n = len(text)
    depth_block = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if depth_block > 0:
            if c == "/" and nxt == "*":
                depth_block += 1
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == "*" and nxt == "/":
                depth_block -= 1
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c != "\n":
                out[i] = " "
            i += 1
            continue
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            if j == -1:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if c == "/" and nxt == "*":
            depth_block = 1
            out[i] = out[i + 1] = " "
            i += 2
            continue
        if c == "r" and (nxt == '"' or nxt == "#"):
            m = re.match(r'r(#*)"', text[i:])
            if m:
                hashes = m.group(1)
                close = '"' + hashes
                j = text.find(close, i + len(m.group(0)))
                j = n if j == -1 else j + len(close)
                for k in range(i, j):
                    if text[k] != "\n":
                        out[k] = " "
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == "'":
            # char literal vs lifetime: 'x' or '\x..' is a literal.
            m = re.match(r"'(\\.[^']*|[^\\'])'", text[i:])
            if m:
                j = i + len(m.group(0))
                for k in range(i, j):
                    if text[k] != "\n":
                        out[k] = " "
                i = j
                continue
        i += 1
    return "".join(out)


def match_brace_span(masked: str, open_idx: int) -> int:
    """Return index just past the brace matching masked[open_idx] == '{'."""
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(masked)


CFG_TEST_RE = re.compile(r"#\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b")


def test_spans(masked: str) -> list[tuple[int, int]]:
    spans = []
    for m in CFG_TEST_RE.finditer(masked):
        brace = masked.find("{", m.end())
        if brace == -1:
            continue
        spans.append((m.start(), match_brace_span(masked, brace)))
    return spans


def in_spans(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= pos < b for a, b in spans)


IMPL_RE = re.compile(r"\bimpl\b[^{;]*?\{", re.DOTALL)


def inherent_impl_spans(masked: str, type_name: str) -> list[tuple[int, int]]:
    """Spans of inherent `impl [..] TypeName [..] {` blocks (not trait impls)."""
    spans = []
    for m in IMPL_RE.finditer(masked):
        header = masked[m.start() : m.end()]
        if " for " in header:
            continue
        if re.search(rf"\b{re.escape(type_name)}\b", header):
            spans.append((m.start(), match_brace_span(masked, m.end() - 1)))
    return spans


# ---------------------------------------------------------------------------
# Workspace model
# ---------------------------------------------------------------------------

@dataclass
class SourceFile:
    path: Path
    rel: str
    text: str
    masked: str
    tests: list[tuple[int, int]]
    nonprod_tree: bool  # under tests/, benches/, examples/

    def line_of(self, pos: int) -> int:
        return self.text.count("\n", 0, pos) + 1


def load_file(path: Path, project_root: Path, dcentrald_root: Path) -> SourceFile:
    text = path.read_text(encoding="utf-8", errors="replace")
    masked = mask_rust(text)
    rel_to_pkg = path.relative_to(dcentrald_root).as_posix()
    nonprod = bool(re.search(r"/(tests|benches|examples)/", "/" + rel_to_pkg))
    return SourceFile(
        path=path,
        rel=path.relative_to(project_root).as_posix(),
        text=text,
        masked=masked,
        tests=test_spans(masked),
        nonprod_tree=nonprod,
    )


def iter_workspace_sources(dcentrald_root: Path):
    """All Rust sources of immediate Cargo packages (src/, tests/, benches/,
    examples/), skipping build output (`target/` at package root)."""
    for manifest in sorted(dcentrald_root.glob("*/Cargo.toml")):
        pkg = manifest.parent
        for sub in ("src", "tests", "benches", "examples"):
            root = pkg / sub
            if root.is_dir():
                yield from sorted(root.rglob("*.rs"))


TYPE_DEF_RE = re.compile(
    r"\bpub(?:\s*\(\s*(?:crate|super|self|in\s+[\w:]+)\s*\))?\s+(?:struct|enum)\s+([A-Z]\w*)"
)
PUB_FN_RE = re.compile(
    r"\bpub(?:\s*\(\s*(?:crate|super|self|in\s+[\w:]+)\s*\))?\s+(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)"
)


@dataclass
class Finding:
    kind: str  # "type" | "method"
    name: str  # allowlist key
    rel: str
    line: int
    detail: str


@dataclass
class Census:
    types_checked: list[str] = field(default_factory=list)
    methods_checked: int = 0
    orphans: list[Finding] = field(default_factory=list)
    live: dict[str, str] = field(default_factory=dict)  # type -> first prod evidence
    scoped_files: int = 0
    empty_globs: list[str] = field(default_factory=list)


def construction_re(type_name: str) -> re.Pattern:
    t = re.escape(type_name)
    return re.compile(rf"\b{t}\s*(?:::\s*\w+|\{{)")


def is_construction_shaped(sf: SourceFile, m: re.Match) -> bool:
    """Reject definition sites, impl headers, use statements, return types."""
    line_start = sf.masked.rfind("\n", 0, m.start()) + 1
    prefix = sf.masked[line_start : m.start()]
    if re.search(r"\b(?:use|pub\s+use|struct|enum|impl|for|dyn|trait)\s*$", prefix):
        return False
    if prefix.rstrip().endswith("->"):
        return False
    if re.match(r"^\s*(?:pub\s+)?use\b", sf.masked[line_start:].lstrip()[:80]):
        return False
    return True


def run_census(project_root: Path) -> Census:
    dcentrald_root = project_root / "dcentrald"
    files = [
        load_file(p, project_root, dcentrald_root)
        for p in iter_workspace_sources(dcentrald_root)
    ]
    by_path = {f.path.resolve(): f for f in files}

    census = Census()

    scoped: list[SourceFile] = []
    for glob in SCOPE_GLOBS:
        matched = 0
        for p in sorted(project_root.glob(glob)):
            sf = by_path.get(p.resolve())
            if sf is not None:
                scoped.append(sf)
                matched += 1
        if matched == 0:
            census.empty_globs.append(glob)
    census.scoped_files = len(scoped)

    # ---- pass 1: type-level construction reachability --------------------
    type_defs: list[tuple[str, SourceFile, int]] = []
    for sf in scoped:
        for m in TYPE_DEF_RE.finditer(sf.masked):
            if in_spans(m.start(), sf.tests):
                continue
            type_defs.append((m.group(1), sf, m.start()))

    for name, def_sf, def_pos in type_defs:
        census.types_checked.append(name)
        pat = construction_re(name)
        prod_evidence = None
        test_only = 0
        self_only = 0
        own_impls = inherent_impl_spans(def_sf.masked, name)
        for sf in files:
            for m in pat.finditer(sf.masked):
                if not is_construction_shaped(sf, m):
                    continue
                if sf.nonprod_tree or in_spans(m.start(), sf.tests):
                    test_only += 1
                    continue
                if sf is def_sf and in_spans(m.start(), own_impls):
                    self_only += 1
                    continue
                if sf is def_sf and abs(m.start() - def_pos) < 4:
                    continue  # the definition itself
                prod_evidence = f"{sf.rel}:{sf.line_of(m.start())}"
                break
            if prod_evidence:
                break
        if prod_evidence:
            census.live[name] = prod_evidence
        else:
            census.orphans.append(
                Finding(
                    kind="type",
                    name=name,
                    rel=def_sf.rel,
                    line=def_sf.line_of(def_pos),
                    detail=(
                        f"zero production constructions "
                        f"(test/self-only: {test_only}/{self_only})"
                    ),
                )
            )

    # ---- pass 2: orphan pub methods on live types -------------------------
    for name, def_sf, _ in type_defs:
        if name not in census.live:
            continue  # whole type already adjudicated by pass 1
        for span_a, span_b in inherent_impl_spans(def_sf.masked, name):
            for fm in PUB_FN_RE.finditer(def_sf.masked, span_a, span_b):
                if in_spans(fm.start(), def_sf.tests):
                    continue
                fn_name = fm.group(1)
                if fn_name in METHOD_NAME_SKIP or fn_name.startswith("open"):
                    continue
                census.methods_checked += 1
                call_pat = re.compile(rf"(?:\.|::)\s*{re.escape(fn_name)}\s*[(:<]")
                called = False
                for sf in files:
                    for cm in call_pat.finditer(sf.masked):
                        if sf is def_sf and abs(cm.start() - fm.start()) < 200:
                            continue  # near the definition (e.g. doc attr)
                        called = True
                        break
                    if called:
                        break
                if not called:
                    census.orphans.append(
                        Finding(
                            kind="method",
                            name=f"{name}::{fn_name}",
                            rel=def_sf.rel,
                            line=def_sf.line_of(fm.start()),
                            detail="zero call-shaped references anywhere (even tests)",
                        )
                    )

    return census


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def verify(census: Census) -> bool:
    found = {f.name: f for f in census.orphans}
    ok = verify_allowlist_reasons()

    for glob in census.empty_globs:
        ok = False
        print(
            f"NO_ORPHAN_POWER_BACKEND_FAIL dead scope glob {glob!r} matches "
            "ZERO files. A scope entry that silently matches nothing is this "
            "gate's own failure mode: everything it was supposed to cover is "
            "unscanned while the gate still reports OK. Either correct the "
            "path (a crate move is the usual cause -- "
            "voltage_rail_adapters.rs moved hal -> asic) or delete the entry "
            "deliberately.",
            file=sys.stderr,
        )

    for f in census.orphans:
        if f.name in TOLERATED_ORPHANS:
            continue
        ok = False
        print(
            f"NO_ORPHAN_POWER_BACKEND_FAIL new orphan {f.kind} {f.name} "
            f"at {f.rel}:{f.line} -- {f.detail}. A pub power/PIC backend "
            "with no production construction site is the recurring failure "
            "this gate exists to block (rank 36 / H4 #7). Either wire it to "
            "a real production caller, delete it, or -- with adjudication -- "
            "add a dated TOLERATED_ORPHANS row explaining why it must ship "
            "unreachable.",
            file=sys.stderr,
        )

    for name, reason in TOLERATED_ORPHANS.items():
        if name not in found:
            ok = False
            print(
                f"NO_ORPHAN_POWER_BACKEND_FAIL stale allowlist row {name!r}: "
                "it is no longer detected as an orphan (wired, renamed, or "
                "deleted). Delete its TOLERATED_ORPHANS entry in the same "
                f"change. Pinned reason was: {reason}",
                file=sys.stderr,
            )

    if ok:
        tolerated = sum(1 for f in census.orphans if f.name in TOLERATED_ORPHANS)
        print(
            "NO_ORPHAN_POWER_BACKEND_OK "
            f"scope_globs={len(SCOPE_GLOBS)} "
            f"scoped_files={census.scoped_files} "
            f"types={len(census.types_checked)} "
            f"methods={census.methods_checked} "
            f"orphans_tolerated={tolerated} new_orphans=0"
        )
    return ok


def print_current(census: Census) -> None:
    print(f"scoped types checked: {len(census.types_checked)}")
    for name in census.types_checked:
        if name in census.live:
            print(f"  LIVE     {name:34} first production evidence {census.live[name]}")
    for f in census.orphans:
        tag = "TOLERATED" if f.name in TOLERATED_ORPHANS else "NEW-ORPHAN"
        print(f"  {tag} {f.kind:6} {f.name} ({f.rel}:{f.line}) {f.detail}")
    print(f"pub methods checked on live types: {census.methods_checked}")


# ---------------------------------------------------------------------------
# Self-test: synthetic fixture proves both detection directions.
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _silenced():
    """Swallow stdout/stderr while running an EXPECTED-FAIL negative control.

    Without this the self-test prints real-looking FAIL lines -- and even a
    stray `NO_ORPHAN_POWER_BACKEND_OK` from the clean-census control -- into
    CI logs that are grepped for exactly those sentinels.
    """
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        yield


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="dcentos-orphan-gate-") as tmp:
        root = Path(tmp)
        hal_src = root / "dcentrald" / "dcentrald-hal" / "src"
        daemon_src = root / "dcentrald" / "dcentrald" / "src"
        hal_src.mkdir(parents=True)
        daemon_src.mkdir(parents=True)
        (root / "dcentrald" / "dcentrald-hal" / "Cargo.toml").write_text(
            "[package]\nname='hal'\n", encoding="utf-8"
        )
        (root / "dcentrald" / "dcentrald" / "Cargo.toml").write_text(
            "[package]\nname='daemon'\n", encoding="utf-8"
        )
        (hal_src / "psu_fixture.rs").write_text(
            "pub struct WiredBackend { x: u8 }\n"
            "impl WiredBackend {\n"
            "    pub fn new() -> Self { WiredBackend { x: 0 } }\n"
            "    pub fn used_method(&self) {}\n"
            "    pub fn dead_method(&self) {}\n"
            "}\n"
            "pub struct GhostBackend { x: u8 }\n"
            "impl GhostBackend {\n"
            "    pub fn new() -> Self { GhostBackend { x: 0 } }\n"
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    use super::*;\n"
            "    #[test]\n"
            "    fn t() { let g = GhostBackend::new(); let _ = g; }\n"
            "}\n",
            encoding="utf-8",
        )
        (daemon_src / "main_fixture.rs").write_text(
            "fn run() {\n"
            "    let b = crate::psu_fixture::WiredBackend::new();\n"
            "    // comment mention of GhostBackend::new() must not count\n"
            '    let s = "GhostBackend::new()";\n'
            "    b.used_method();\n"
            "    let _ = s;\n"
            "}\n",
            encoding="utf-8",
        )

        import unittest.mock as _mock

        with _mock.patch.object(
            sys.modules[__name__],
            "SCOPE_GLOBS",
            ("dcentrald/dcentrald-hal/src/psu*.rs",),
        ):
            census = run_census(root)

        orphan_names = {f.name for f in census.orphans}
        if "GhostBackend" not in orphan_names:
            print(
                "NO_ORPHAN_SELFTEST_FAILED: test-only-constructed GhostBackend "
                f"was not flagged (orphans={sorted(orphan_names)}; comment and "
                "string mentions must not count as production evidence)",
                file=sys.stderr,
            )
            return False
        if "WiredBackend" not in census.live:
            print(
                "NO_ORPHAN_SELFTEST_FAILED: production-constructed WiredBackend "
                "was wrongly flagged as an orphan",
                file=sys.stderr,
            )
            return False
        if "WiredBackend::dead_method" not in orphan_names:
            print(
                "NO_ORPHAN_SELFTEST_FAILED: never-called pub dead_method on a "
                "live type was not flagged",
                file=sys.stderr,
            )
            return False
        if "WiredBackend::used_method" in orphan_names:
            print(
                "NO_ORPHAN_SELFTEST_FAILED: called used_method was wrongly "
                "flagged",
                file=sys.stderr,
            )
            return False

        # -- SCOPE CHECK negative control: a glob matching nothing must be
        #    reported, not silently ignored (the Round-16 B6 defect).
        with _mock.patch.object(
            sys.modules[__name__],
            "SCOPE_GLOBS",
            (
                "dcentrald/dcentrald-hal/src/psu*.rs",
                "dcentrald/dcentrald-hal/src/this_file_does_not_exist.rs",
            ),
        ):
            dead = run_census(root)
        if "dcentrald/dcentrald-hal/src/this_file_does_not_exist.rs" not in (
            dead.empty_globs
        ):
            print(
                "NO_ORPHAN_SELFTEST_FAILED: a SCOPE_GLOBS entry matching zero "
                f"files was not reported (empty_globs={dead.empty_globs}). A "
                "dead scope glob silently unscans everything it named.",
                file=sys.stderr,
            )
            return False
        if not dead.orphans and dead.scoped_files == 0:
            print(
                "NO_ORPHAN_SELFTEST_FAILED: dead-glob fixture scanned nothing "
                "at all, so the control proves nothing",
                file=sys.stderr,
            )
            return False

    # verify() must REFUSE on a dead glob even when nothing else is wrong.
    # Synthetic census + empty allowlist isolates the scope check from the
    # real ledger (a fixture census would otherwise report every real row
    # stale and mask which check actually fired).
    clean = Census()
    clean.empty_globs = ["dcentrald/definitely/not/here/*.rs"]
    with _mock.patch.dict(
        sys.modules[__name__].TOLERATED_ORPHANS, {}, clear=True
    ):
        with _silenced():
            dead_glob_refused = not verify(clean)
            clean_census_accepted = verify(Census())
    if not dead_glob_refused:
        print(
            "NO_ORPHAN_SELFTEST_FAILED: verify() returned OK despite a dead "
            "scope glob and no other finding",
            file=sys.stderr,
        )
        return False
    if not clean_census_accepted:
        print(
            "NO_ORPHAN_SELFTEST_FAILED: verify() rejected a clean census with "
            "no dead globs -- the scope check is over-firing",
            file=sys.stderr,
        )
        return False

    # -- REASON CHECK negative control: a blank / undated reason must FAIL.
    real = dict(TOLERATED_ORPHANS)
    if not real:
        print(
            "NO_ORPHAN_SELFTEST_FAILED: TOLERATED_ORPHANS is empty",
            file=sys.stderr,
        )
        return False
    if not verify_allowlist_reasons():
        print(
            "NO_ORPHAN_SELFTEST_FAILED: the real allowlist does not satisfy "
            "its own reason-quality rule",
            file=sys.stderr,
        )
        return False
    victim = next(iter(real))
    # Three controls, one per failure mode the reason check must cover:
    #   ""              -> reason deleted outright
    #   "wired later"   -> short prose, no date
    #   "2026-08-07: x" -> correctly DATED but contentless. Isolates the
    #                      MIN_CHARS rule: without it, setting MIN_CHARS to 0
    #                      leaves the self-test green (B6 mutation M6).
    #   long-but-undated-> isolates the DATED_REASON_RE rule: without it,
    #                      neutering the regex leaves the self-test green,
    #                      because MIN_CHARS alone still catches the three
    #                      short controls (B6 mutation M7).
    # Each control must be caught by exactly the sub-rule it targets; two
    # overlapping rules with only overlapping controls verify neither.
    for bad_reason, label in (
        ("", "blank"),
        ("wired later", "undated stub"),
        ("2026-08-07: x", "dated but contentless"),
        (
            "space-heater room-temp PID; deliberate non-instantiation per the "
            "REST truth contract, do not wire without a setpoint endpoint",
            "substantive but undated",
        ),
    ):
        with _mock.patch.dict(
            sys.modules[__name__].TOLERATED_ORPHANS,
            {victim: bad_reason},
            clear=False,
        ):
            with _silenced():
                stub_accepted = verify_allowlist_reasons()
            if stub_accepted:
                print(
                    f"NO_ORPHAN_SELFTEST_FAILED: a {label} reason on "
                    f"{victim!r} passed the reason check. Stripping the WHY "
                    "must fail loudly -- that is what stops a cleanup wave "
                    "from deleting a deliberate fail-closed scaffold.",
                    file=sys.stderr,
                )
                return False

    print("NO_ORPHAN_SELFTEST_OK")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-current", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return 0 if self_test() else 1

    project_root = Path(__file__).resolve().parents[1]
    census = run_census(project_root)
    if args.print_current:
        print_current(census)
        return 0
    return 0 if verify(census) else 1


if __name__ == "__main__":
    raise SystemExit(main())
