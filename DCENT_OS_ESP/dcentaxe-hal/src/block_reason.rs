//! Host-pure fail-closed reason codes and the 128x32 panel rows that carry
//! them.
//!
//! Same split, and the same reason for it, as `display_convert.rs`: this module
//! is compiled **unconditionally** (no `display-*` feature gate) and re-included
//! into `dcentaxe-core` via `#[path]`, so every string an operator can be shown
//! when their board refuses to mine is executable, renderable and assertable on
//! a host. `main.rs` is `target_os = "espidf"` and can never be host-compiled,
//! so anything it composes inline is, by construction, untested.
//!
//! # The defect this module closes (lane P1-O1)
//!
//! `main.rs` set `mining_block_reason` to a sentence — 29 assignment sites,
//! 30–80 characters each — and handed that sentence straight to
//! [`crate::display_convert::FrameBuffer::draw_text`], which clips at column 21
//! **from the right, silently, with no ellipsis**. Every one of the 29 was
//! clipped; the longest lost 50 of its 71 characters and read
//! `Board has no rail act`. The one piece of information the operator most
//! needs — *why the miner will not mine, and what to do about it* — was the one
//! the panel destroyed.
//!
//! The fix is the shape the `oled_panel_budget_guards` ratchet named when it
//! measured the damage: **a short code plus a pointer**. Each cause resolves to
//!
//! * a [`BlockReason::code`] of at most [`CODE_COLUMNS`] characters, so the
//!   error marker still fits ahead of it on a 21-column row, and
//! * a [`BlockReason::action`] of at most
//!   [`TEXT_COLUMNS`](crate::display_convert::TEXT_COLUMNS) characters — the
//!   next thing to do, in the imperative, on its own row.
//!
//! The full sentence is NOT lost: it lives on as [`BlockReason::summary`], is
//! written to the log beside the code, and every assignment site keeps (or
//! gains) its own `error!` carrying the underlying driver error, so the
//! diagnostic detail an interpolated `{}` used to add is still in the log.
//!
//! # Dedupe is deliberate
//!
//! 29 sites collapse to [`BlockReason::COUNT`] codes. Sites that differ only in
//! a part number the operator cannot change (EMC2101 vs EMC2302 vs EMC2103 fan
//! init) or only in an interpolated value share one code; the part number and
//! the value stay in the log, where there is room for them. A code the operator
//! must translate back into a part number is not a shorter reason, it is a
//! worse one.
//!
//! # What this module deliberately does NOT do
//!
//! It owns TEXT only. Not one gate condition, threshold, ordering rule or
//! side effect in `main.rs`'s boot path is expressed here, and nothing here is
//! consulted before a refusal — a [`BlockReason`] is chosen *after*
//! `mining_permitted = false` has already been written, exactly where the
//! sentence used to be built.

use crate::display_convert::{fit_line, line_fits, TEXT_COLUMNS};

/// The error marker that distinguishes a fail-closed screen from a status
/// screen at arm's length.
///
/// `CRITIC_RUBRIC.md` §4.2 asks for "a full-width marker, inverted band, or
/// `!!` prefix"; `!!` is what the runtime urgent notifications already use
/// (`!! POWER FAULT !!`, `!! OVER-CURRENT !!`, `!! FAN STALL !!`), so the panel
/// keeps one vocabulary for "this is not a normal screen". A bracketing
/// second `!!` would cost three more columns than the widest code can spare.
pub const MARKER: &str = "!!";

/// The column budget a [`BlockReason::code`] must fit.
///
/// [`code_row`] renders `"!! " + code`, so the code gets the panel's 21 columns
/// minus the marker and its separating space. A code that used all 21 would
/// push the marker off the row — which is the failure mode this whole lane
/// exists to end, one row up.
pub const CODE_COLUMNS: usize = TEXT_COLUMNS - MARKER.len() - 1;

/// Columns an occurrence count needs at its widest (` x255`), for the reasons
/// that carry one.
pub const COUNT_COLUMNS: usize = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Actions
// ─────────────────────────────────────────────────────────────────────────────
//
// Six of them, deliberately. Every code maps onto one, and every one of them is
// something the operator can actually DO — never a promise about the outcome.
// "Power-cycle to retry" says what to try, not that it will work; a transient
// I2C failure often clears and a dead regulator never does, and the panel is
// not in a position to tell them apart.

/// The reason is structural or needs detail the panel cannot hold: read it in
/// full on the dashboard.
pub const SEE_DASHBOARD: &str = "See dashboard";
/// The operator's own configuration was refused; the dashboard is where it is
/// changed.
pub const FIX_IN_DASHBOARD: &str = "Fix in dashboard";
/// Safe mode has an explicit dashboard control (`POST
/// /api/system/clear-safe-mode`), which is far too long for the panel.
pub const CLEAR_IN_DASHBOARD: &str = "Clear in dashboard";
/// A bring-up step failed in a way a fresh power-on may or may not clear.
pub const RETRY_POWER_CYCLE: &str = "Power-cycle to retry";
/// Fan tach proof is missing: the fans themselves are the thing to look at.
pub const CHECK_FANS: &str = "Check fans; reboot";
/// The plug-sense gate never saw input power.
pub const CHECK_POWER_INPUT: &str = "Check power input";

// ─────────────────────────────────────────────────────────────────────────────
// Reasons
// ─────────────────────────────────────────────────────────────────────────────

/// Why `main.rs` refused to mine, in a form the 128x32 panel can render whole.
///
/// The discriminant is the index into [`REASONS`]; [`BlockReason::ALL`] lists
/// every variant in that order and a test pins the two together, so a variant
/// added without its row cannot compile past the guard.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockReason {
    /// `config.validate_safety()` refused the stored configuration.
    ConfigUnsafe,
    /// Repeated task-watchdog resets put the firmware in safe mode. Carries the
    /// reset count (see [`BlockReason::carries_count`]).
    SafeModeWdt,
    /// The plug-sense gate reports no input power.
    NoPlugSense,
    /// The thermal I2C bus multiplexer would not select its channel.
    ThermalMux,
    /// The TMP451 die-sensor set is unavailable or failed to initialize.
    ThermalDieSensor,
    /// The TMP1075 board sensor set failed to initialize.
    ThermalBoardSensor,
    /// No trusted temperature source returned data at boot.
    ThermalNoSource,
    /// The fan controller failed to initialize.
    FanInit,
    /// A fan speed write failed.
    FanSet,
    /// A declared fan produced no tachometer reading at boot.
    FanNoTach,
    /// The fan controller this board declares did not answer.
    FanMissing,
    /// The rail port-expander (FXL6408) could not be found or configured.
    RailExpander,
    /// The ASIC LDO enable failed (GPIO or expander pin).
    RailLdo,
    /// The buck/VREG enable failed (GPIO or expander pin, immediate or
    /// deferred).
    RailBuck,
    /// The board has no rail actuator at all.
    RailNoActuator,
    /// The board has no enable GPIO and its regulator cannot cut the rail over
    /// I2C.
    RailNoI2cCut,
    /// `PowerManager::new` failed after its retries.
    PowerInit,
    /// The core-voltage write failed.
    PowerSetVoltage,
    /// A hardware safety gate refused without naming itself — the fallback, and
    /// the only variant no assignment site selects.
    SafetyGate,
}

/// One row of the reason table: what the panel shows, what to do, and the full
/// sentence for the log.
struct ReasonRow {
    code: &'static str,
    action: &'static str,
    summary: &'static str,
}

/// The table, indexed by `BlockReason as usize`.
///
/// One array rather than three `match` expressions: the panel path reads all
/// three fields, and a single indexed table is both smaller in the image and
/// impossible to leave half-updated when a variant is added.
static REASONS: [ReasonRow; BlockReason::COUNT] = [
    ReasonRow {
        code: "CONFIG:UNSAFE",
        action: FIX_IN_DASHBOARD,
        summary: "Config safety validation failed",
    },
    ReasonRow {
        code: "SAFE-MODE WDT",
        action: CLEAR_IN_DASHBOARD,
        summary: "SAFE MODE: task-WDT resets. POST /api/system/clear-safe-mode to recover.",
    },
    ReasonRow {
        code: "POWER:NO-PLUG",
        action: CHECK_POWER_INPUT,
        summary: "Power input not detected by plug-sense gate",
    },
    ReasonRow {
        code: "THERMAL:MUX",
        action: RETRY_POWER_CYCLE,
        summary: "Thermal I2C mux channel select failed",
    },
    ReasonRow {
        code: "THERMAL:DIE-SENSOR",
        action: RETRY_POWER_CYCLE,
        summary: "TMP451 diode mux unavailable or its sensors failed to initialize",
    },
    ReasonRow {
        code: "THERMAL:BOARD-SNS",
        action: RETRY_POWER_CYCLE,
        summary: "TMP1075 sensor init failed",
    },
    ReasonRow {
        code: "THERMAL:NO-SRC",
        action: SEE_DASHBOARD,
        summary: "No trusted thermal source returned data at boot",
    },
    ReasonRow {
        code: "FAN:INIT",
        action: RETRY_POWER_CYCLE,
        summary: "Fan controller init failed",
    },
    ReasonRow {
        code: "FAN:SET",
        action: RETRY_POWER_CYCLE,
        summary: "Fan speed write failed",
    },
    ReasonRow {
        code: "FAN:NO-TACH",
        action: CHECK_FANS,
        summary: "Required fan tach absent at boot",
    },
    ReasonRow {
        code: "FAN:MISSING",
        action: SEE_DASHBOARD,
        summary: "Expected fan controller missing",
    },
    ReasonRow {
        code: "RAIL:EXPANDER",
        action: RETRY_POWER_CYCLE,
        // Selected at three sites: power-sequence setup failed, expander not found at its address,
        // deferred enable failed (DCENT_EE pre-merge review, LOW-2). The site's own error! line
        // carries the specific cause and address; this summary must not claim only one of them.
        summary: "Expander power-sequence setup failed, expander not found, or deferred enable failed",
    },
    ReasonRow {
        code: "RAIL:LDO",
        action: RETRY_POWER_CYCLE,
        summary: "ASIC LDO enable failed",
    },
    ReasonRow {
        code: "RAIL:BUCK",
        action: RETRY_POWER_CYCLE,
        summary: "Buck enable failed",
    },
    ReasonRow {
        code: "RAIL:NO-ACTUATOR",
        action: SEE_DASHBOARD,
        summary: "Board has no rail actuator: no enable GPIO and no commandable regulator",
    },
    ReasonRow {
        code: "RAIL:NO-I2C-CUT",
        action: SEE_DASHBOARD,
        summary: "No enable GPIO and no I2C-cuttable regulator",
    },
    ReasonRow {
        code: "POWER:INIT",
        action: RETRY_POWER_CYCLE,
        summary: "Power init failed",
    },
    ReasonRow {
        code: "POWER:SET-VOLTAGE",
        action: RETRY_POWER_CYCLE,
        summary: "Set voltage failed",
    },
    ReasonRow {
        code: "SAFETY:GATE",
        action: SEE_DASHBOARD,
        summary: "Hardware safety gate",
    },
];

impl BlockReason {
    /// How many reasons exist. Kept next to [`REASONS`] so the array length and
    /// [`BlockReason::ALL`] cannot drift apart silently.
    pub const COUNT: usize = 19;

    /// Every reason, in discriminant order.
    pub const ALL: [BlockReason; BlockReason::COUNT] = [
        BlockReason::ConfigUnsafe,
        BlockReason::SafeModeWdt,
        BlockReason::NoPlugSense,
        BlockReason::ThermalMux,
        BlockReason::ThermalDieSensor,
        BlockReason::ThermalBoardSensor,
        BlockReason::ThermalNoSource,
        BlockReason::FanInit,
        BlockReason::FanSet,
        BlockReason::FanNoTach,
        BlockReason::FanMissing,
        BlockReason::RailExpander,
        BlockReason::RailLdo,
        BlockReason::RailBuck,
        BlockReason::RailNoActuator,
        BlockReason::RailNoI2cCut,
        BlockReason::PowerInit,
        BlockReason::PowerSetVoltage,
        BlockReason::SafetyGate,
    ];

    #[inline]
    fn row(self) -> &'static ReasonRow {
        &REASONS[self as usize]
    }

    /// The panel code: at most [`CODE_COLUMNS`] characters, uppercase, with a
    /// `SUBSYSTEM:DETAIL` shape so a photograph of the panel sorts an operator
    /// into the right half of the dashboard before they read a word of it.
    #[inline]
    pub fn code(self) -> &'static str {
        self.row().code
    }

    /// What to do next: at most one panel row, imperative, no promises.
    #[inline]
    pub fn action(self) -> &'static str {
        self.row().action
    }

    /// The full sentence — the text that used to be handed to the panel and
    /// clipped. It goes to the log, where there is room for it.
    #[inline]
    pub fn summary(self) -> &'static str {
        self.row().summary
    }

    /// Whether this reason's code row carries an occurrence count.
    ///
    /// Only safe mode does today: "how many watchdog resets" is the difference
    /// between a one-off and a board that cannot stay up, and it is the single
    /// number an operator needs before deciding whether clearing safe mode is
    /// reasonable. Every other count belongs in the log.
    #[inline]
    pub const fn carries_count(self) -> bool {
        matches!(self, BlockReason::SafeModeWdt)
    }
}

/// The bare code, with the occurrence count appended where the reason carries
/// one and the count still fits.
///
/// Composed with [`fit_line`], not by hand: the count is OPTIONAL, so it is
/// dropped before it could push the code off the row. `count` is ignored by
/// every reason for which [`BlockReason::carries_count`] is false, so the call
/// site does not have to know which those are.
pub fn code_line(reason: BlockReason, count: u8) -> String {
    if reason.carries_count() {
        let tail = format!("x{count}");
        fit_line(&[reason.code()], &[tail.as_str()], CODE_COLUMNS)
    } else {
        reason.code().to_string()
    }
}

/// The panel's code row: the error marker, then [`code_line`].
///
/// Bounded by construction — [`CODE_COLUMNS`] is exactly what is left of the
/// row after the marker, and a test walks every reason and every count to prove
/// the composed row never exceeds the panel.
pub fn code_row(reason: BlockReason, count: u8) -> String {
    let line = code_line(reason, count);
    fit_line(&[MARKER, line.as_str()], &[], TEXT_COLUMNS)
}

/// The `IP: …` row.
///
/// The address is an OPTIONAL word, so an address that cannot fit is DROPPED
/// rather than clipped. A clipped address is worse than none: `IP: 203.0.113.10`
/// truncated from `…102` is still a syntactically valid address, and an operator
/// would type it.
pub fn ip_row(ip: &str) -> String {
    fit_line(&["IP:"], &[ip], TEXT_COLUMNS)
}

/// The four rows of the fail-closed screen, in `show_status` order.
///
/// `rung_row` is passed in rather than composed here so the rung the screen
/// claims stays visible at the call site in `main.rs` — the `dcentaxe-core`
/// source contract reads that expression to prove which rung the panel and the
/// dashboard agree on, and a helper that swallowed it would hide exactly that.
pub fn blocked_screen(rung_row: &str, reason: BlockReason, count: u8, ip: &str) -> [String; 4] {
    [
        rung_row.to_string(),
        code_row(reason, count),
        reason.action().to_string(),
        ip_row(ip),
    ]
}

/// Whether every row of a composed screen fits the panel.
pub fn screen_fits(rows: &[String; 4]) -> bool {
    rows.iter().all(|row| line_fits(row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_and_the_variant_list_describe_the_same_set() {
        assert_eq!(REASONS.len(), BlockReason::COUNT);
        assert_eq!(BlockReason::ALL.len(), BlockReason::COUNT);
        for (i, reason) in BlockReason::ALL.iter().enumerate() {
            assert_eq!(
                *reason as usize, i,
                "BlockReason::ALL is not in discriminant order at index {i}; \
                 `row()` indexes REASONS by the discriminant, so a reordered \
                 ALL would silently give a reason another reason's code"
            );
        }
    }

    #[test]
    fn every_code_fits_the_row_that_carries_the_error_marker() {
        for reason in BlockReason::ALL {
            let code = reason.code();
            let cols = code.chars().count();
            assert!(!code.is_empty(), "{reason:?} has an empty code");
            assert!(
                cols <= CODE_COLUMNS,
                "{reason:?} code {code:?} is {cols} columns; the marker row only \
                 has {CODE_COLUMNS} left after {MARKER:?} and its space"
            );
            assert!(
                code.is_ascii(),
                "{reason:?} code {code:?} is not ASCII; the 5x7 font covers \
                 32..127 only and anything else renders blank"
            );
            if reason.carries_count() {
                assert!(
                    cols + COUNT_COLUMNS <= CODE_COLUMNS,
                    "{reason:?} carries a count but {code:?} leaves no room for \
                     ` x255`, so the widest count would be silently dropped"
                );
            }
        }
    }

    #[test]
    fn every_action_fits_the_panel_and_names_something_to_do() {
        for reason in BlockReason::ALL {
            let action = reason.action();
            assert!(!action.is_empty(), "{reason:?} has no action");
            assert!(
                line_fits(action),
                "{reason:?} action {action:?} is {} columns, the panel holds {TEXT_COLUMNS}",
                action.chars().count()
            );
            assert!(action.is_ascii(), "{reason:?} action {action:?} is not ASCII");
        }
    }

    #[test]
    fn every_summary_is_a_sentence_and_none_is_empty() {
        for reason in BlockReason::ALL {
            let summary = reason.summary();
            assert!(!summary.is_empty(), "{reason:?} has no summary");
            assert!(
                summary.chars().count() >= 15,
                "{reason:?} summary {summary:?} is too short to be the full \
                 sentence the log is supposed to keep"
            );
        }
    }

    /// Two reasons sharing a code would make the panel ambiguous exactly where
    /// it is meant to be decisive.
    #[test]
    fn no_two_reasons_share_a_code() {
        let mut seen: Vec<&str> = Vec::new();
        for reason in BlockReason::ALL {
            assert!(
                !seen.contains(&reason.code()),
                "{reason:?} reuses the code {:?}",
                reason.code()
            );
            seen.push(reason.code());
        }
    }

    /// The widest interpolated variant, proven over its whole domain rather
    /// than at a convenient sample.
    #[test]
    fn the_counted_code_row_fits_for_every_possible_count() {
        for reason in BlockReason::ALL {
            for count in 0u16..=255 {
                let count = count as u8;
                let row = code_row(reason, count);
                assert!(
                    line_fits(&row),
                    "{reason:?} at count {count} composes {row:?} = {} columns",
                    row.chars().count()
                );
                assert!(
                    row.starts_with(MARKER),
                    "{reason:?} lost its error marker at count {count}: {row:?}"
                );
                assert!(
                    row.contains(reason.code()),
                    "{reason:?} lost its code at count {count}: {row:?}"
                );
            }
        }
        // The count is carried where it is declared, and only there.
        assert_eq!(code_row(BlockReason::SafeModeWdt, 3), "!! SAFE-MODE WDT x3");
        assert_eq!(
            code_row(BlockReason::SafeModeWdt, 255),
            "!! SAFE-MODE WDT x255"
        );
        assert_eq!(code_row(BlockReason::PowerInit, 255), "!! POWER:INIT");
    }

    #[test]
    fn the_ip_row_drops_an_address_it_cannot_render_whole() {
        assert_eq!(ip_row("203.0.113.42"), "IP: 203.0.113.42");
        assert_eq!(ip_row("255.255.255.255"), "IP: 255.255.255.255");
        assert_eq!(ip_row(""), "IP:");
        // 18 characters would need 22 columns with the label; the address is
        // dropped whole rather than truncated into a plausible-looking lie.
        assert_eq!(ip_row("2001:db8::1234:5678"), "IP:");
        assert!(line_fits(&ip_row("255.255.255.255")));
    }

    #[test]
    fn every_fail_closed_screen_fits_the_panel_whole() {
        use crate::display_convert::{rung_status_line, MiningRung};

        let rung = rung_status_line(MiningRung::Standby.panel_word(), "disabled");
        for reason in BlockReason::ALL {
            for ip in ["", "203.0.113.1", "203.0.113.42", "255.255.255.255"] {
                for count in [0u8, 3, 255] {
                    let rows = blocked_screen(&rung, reason, count, ip);
                    assert!(
                        screen_fits(&rows),
                        "{reason:?} / ip {ip:?} / count {count} composes a row the \
                         panel clips: {rows:#?}"
                    );
                    assert_eq!(rows[0], rung, "row 0 must carry the rung verbatim");
                    assert_eq!(rows[2], reason.action(), "row 2 must be the action");
                    assert!(rows[3].starts_with("IP:"), "row 3 must be the IP row");
                }
            }
        }
    }

    /// The trade this lane makes, stated as an assertion: the panel gets the
    /// code, the log keeps the sentence, and the code is never the longer of
    /// the two.
    #[test]
    fn the_code_is_always_shorter_than_the_sentence_it_replaces() {
        for reason in BlockReason::ALL {
            let (code, summary) = (reason.code(), reason.summary());
            assert!(
                code.chars().count() < summary.chars().count(),
                "{reason:?}: the code {code:?} is not shorter than the sentence \
                 {summary:?} it stands in for — then it is not a code, and the \
                 indirection buys nothing"
            );
        }
        // The canonical clipped reason, the one `oled_panel_budget_guards`
        // named when it measured the damage (71 characters, 21 rendered).
        assert!(!line_fits(BlockReason::RailNoActuator.summary()));
        assert!(line_fits(BlockReason::RailNoActuator.code()));
    }
}
