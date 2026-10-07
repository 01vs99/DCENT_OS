//! Exact per-bin BM1366 XP-pair board profiles, full-unit population
//! admission, per-model PSU dialect selection, chain-init sequencing and
//! all-chain work distribution for the two resolved Amlogic BM1366 bins
//! (campaign `2026-09-07-antminer-beta-execution`, lane R12; findings.md row
//! "S19 XP/j XP BM1366"). Pure and no-I/O: this module plans and refuses; it
//! never opens a UART, touches GPIO437, or grants electrical authority.
//!
//! The pair is deliberately TWO bins, never one merged profile (root
//! : their measured PSU version selects modern APW12 (75..77) or
//! APW17 (c1); the two rows "must never be merged"). The S19k 77-chip
//! program is NOT generalized here: S19k stays its own row in
//! [`crate::bm1366_serial_platform`] with its own geometry, HCN value and
//! Braiins 54-byte work dialect.
//!
//! Geometry (each bin is a distinct platform; neither is an S19k alias):
//!
//! | Bin | Board target | Factory boards | Domains x chips | Chips/chain | Chains | Chips/unit |
//! |---|---|---|---:|---:|---:|---:|
//! | S19 XP | `am3-s19xp` | BHB56801, BHB56802 | 11 x 10 | 110 | 3 | 330 |
//! | S19j XP | `am3-s19jxp` | BHB56804 | 11 x 10 | 110 | 3 | 330 |
//!
//! Citations per datum:
//! - Stock contracts: held minerfs trees
//!
//!   (default topol.conf == topol_BHB56801.conf, sha256
//!   `f4586a3b09fc9b7ce48f01272d4d06a19bea85d23d68ce2bb1b3dbf9bebd529d`:
//!   BM1366, 3 chains, 110/chain = 11 dom x 10, addr interval 2, PSU APW12)
//!   and `.../s19j-xp-merge-20241014/` (default topol.conf, sha256
//!   `37e0db670b673ea6167749b88349fc67060fcc5a87af8812f4d85162b0c467bd`:
//!   BHB56804, BM1366, 3 chains, 110/chain, addr interval 2, PSU APW17
//!   v[193]). The full citation blocks live on the dispatch rows in
//!   [`crate::bm1366_serial_platform::{AM3_S19XP_STOCK_BASIS,
//!   AM3_S19JXP_STOCK_BASIS}] — internal RE evidence only.
//! - Production PSU selection: held S21 production bosminer
//!    (SHA-256
//!   `64e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1`),
//!   via `evidence/r12/s19xp-modern-psu-selection.asm` (XP constructor
//!   block `0x6f82d0`, BHB56801/56802, 110-chip) and
//!   `evidence/r12/s19jxp-modern-psu-selection.asm` (jXP constructor block
//!   `0x6f77ec`, BHB56804). Each constructor binds its own PSU dialect
//!   through factory `0x8c7a10` (`PsuAsVoltageController`); the XP model
//!   never selects the jXP APW17 path and vice versa.
//! - Runtime PSU version law: root  load-bearing GPIO paragraph —
//!   "Their measured PSU version selects modern APW12 (75..77) or APW17
//!   (c1); other variants are not inferred." This module mirrors the
//!   numeric law of the retained wire owner
//!   `dcentrald-hal::platform::amlogic::s21_psu::ProductionProfile::select`
//!   (XP row -> `S21Apw121215`, jXP row -> `ModernApw171215`); dcentrald-common
//!   cannot depend on dcentrald-hal, so the numeric agreement is pinned by
//!   tests on both sides and in `evidence/r12/SOURCE_NOTE.md`.
//! - UART routes: held AML key3 controller registry (`evidence/r14/
//!   production-profile-checkpoint.md`, "AML controller registry";
//!   physical slots 1/2/3 -> ttyS3/ttyS2/ttyS1), the same retained routes
//!   as `dcentrald-hal::platform::amlogic::S21_UARTS` and the R12 PTY
//!   replay's slot-0 -> `/dev/ttyS3` binding.
//! - GPIO437 polarity: AM3 software mapping raw 0 = ON, raw 1 = OFF for
//!   both bins, joined through their production model -> ASIC profile ->
//!   PSU-controller factory chain (root ; R14
//!   `production-model-psu-selection.asm`; retained HAL owner
//!   `AmlogicNoPicProfile::{S19Xp,S19jXp}::psu_is_active_low() == true`,
//!   `AmlogicPsuCommitAuthority::reset_after_cut == true`). Software
//!   traces, NOT DMM rail measurements.
//! - Chip attribution: the BM1366 nonce response carries the finding
//!   chip's ASSIGNED address in bits [24:17]
//!   (`dcentrald-asic/src/drivers/bm1366.rs::decode_nonce`). Chain-level
//!   attribution (which UART produced a share) is exact, and the address
//!   field normalizes onto the assigned ladder (interval 2); physical
//!   per-chip health/attribution for autotuning stays a bench matter and
//!   is never fabricated here.

use crate::s21_generation_admission::ColdInitStage;

/// BM1366 chip ID (driver `dcentrald-asic/src/drivers/bm1366.rs::CHIP_ID`;
/// stock topol `asic == 0x1366`, 112 big + 894 small cores).
pub const BM1366_CHIP_ID: u16 = 0x1366;

/// Every resolved XP-pair full unit presents three hashboard chains (stock
/// topol `chain_num` 3 on both merges; live 3-board population remains a
/// bench capture datum — subsets stay admissible per chain below).
pub const BM1366_XP_CHAINS_PER_UNIT: u8 = 3;

/// Stock and runtime address interval agree: stock topol declares interval
/// 2 and the shared truncated-byte-space plan yields 256/110 = 2
/// (`dcentrald_api_types::asic_command::LinearAddressPlan`;
/// `SerialMiner::serial_address_interval`).
pub const BM1366_XP_ADDRESS_INTERVAL: u8 = 2;

/// Verified AM3 physical-slot UART routes for the XP pair (same retained
/// routes as the S21-family native bins): physical slots 1/2/3 map to
/// ttyS3/ttyS2/ttyS1 (AML key3 controller registry; retained in
/// `dcentrald-hal::platform::amlogic::S21_UARTS`).
pub const AM3_S19XP_UART_ROUTES: [&str; 3] = ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"];

/// Resolved BM1366 XP-pair board bins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1366XpBin {
    /// Antminer S19 XP (APW12 modern dialect).
    Xp,
    /// Antminer S19j XP (APW17 modern dialect; never merged with XP).
    Jxp,
}

/// Exact per-bin profile. Geometry and names are evidence-backed; PSU
/// dialect is per-model fixed (measured-version gated), unlike the S21
/// Pro/XP measured-auto scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1366XpBoardProfile {
    pub bin: Bm1366XpBin,
    /// Campaign board target; identical to the dispatch-admitted rows in
    /// [`crate::bm1366_serial_platform::BM1366_SERIAL_PLATFORMS`].
    pub board_target: &'static str,
    /// Exact factory hashboard names that may select this bin. BHB56801/02
    /// for XP and BHB56804 for jXP match
    /// `serial_mining::s21_native_identity::validate_bm1366_xp_pages`.
    /// BHB56806 (XP 110/chain sibling, no runtime identity fixture) and
    /// BHB56807 (jXP sibling, APW17 v[194]) are NOT admitted — unknown
    /// profiles stay outside this exact runtime.
    pub board_names: &'static [&'static str],
    pub domains_per_board: u8,
    pub chips_per_domain: u8,
    /// Exact full-chain ASIC population (110 = 11 domains x 10). An
    /// off-by-one observation refuses before any work is planned.
    pub chips_per_chain: u16,
}

impl Bm1366XpBoardProfile {
    /// S19 XP: 11 domains x 10 = 110 chips per chain, 3 x 110 = 330 per
    /// unit; PSU dialect APW12 modern (measured 0x75..=0x77 only).
    pub const XP: Self = Self {
        bin: Bm1366XpBin::Xp,
        board_target: "am3-s19xp",
        board_names: &["BHB56801", "BHB56802"],
        domains_per_board: 11,
        chips_per_domain: 10,
        chips_per_chain: 110,
    };

    /// S19j XP: same 11x10=110 geometry, distinct platform; PSU dialect
    /// APW17 modern (measured 0xc1 only). BHB56807/v[194] is not inferred.
    pub const JXP: Self = Self {
        bin: Bm1366XpBin::Jxp,
        board_target: "am3-s19jxp",
        board_names: &["BHB56804"],
        domains_per_board: 11,
        chips_per_domain: 10,
        chips_per_chain: 110,
    };

    /// Both resolved bins, XP / jXP order (the pair is exactly these two).
    pub const ALL: [Self; 2] = [Self::XP, Self::JXP];

    /// Exact profile for a campaign board target, else `None`.
    pub fn for_board_target(target: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.board_target == target)
    }

    /// Exact profile for a decoded factory board name, else `None`.
    /// BHB56804 must never select XP and BHB56801/02 must never select jXP
    /// (cross-bin refusal is pinned by tests here and by
    /// `s21_native_identity::validate_bm1366_xp_pages`). The S19k
    /// BHB569xx family, BHB56806 and BHB56807 select nothing.
    pub fn for_board_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.board_names.contains(&name))
    }

    /// Exact full-unit ASIC count at the bin geometry: 330 for both bins.
    pub const fn chips_per_unit(&self) -> u16 {
        self.chips_per_chain * (BM1366_XP_CHAINS_PER_UNIT as u16)
    }

    /// Verified physical UART routes (retained AML registry mapping).
    pub const fn uart_routes(&self) -> &'static [&'static str; 3] {
        &AM3_S19XP_UART_ROUTES
    }

    /// Board_target-scoped GPIO437 polarity evidence: both bins join the
    /// AM3 software mapping raw 0 = ON / raw 1 = OFF through their
    /// production model -> ASIC-profile -> PSU-controller factory chain.
    /// Never construct an electrical command from the software mapping
    /// alone: it is not a DMM rail measurement, and terminal SafeOff
    /// admission still requires the retained HAL/physical proof path
    /// (`AmlogicPsuCommitAuthority` cut-first/reset-second custody).
    pub const fn power_polarity(&self) -> Bm1366XpPowerPolarity {
        Bm1366XpPowerPolarity::Am3MappedZeroOnOneOff
    }

    /// The bin's fixed PSU dialect. Unlike S21 Pro/XP (measured auto), the
    /// XP pair is per-model: the XP model's production constructor selects
    /// the APW12 dialect, the jXP model's constructor selects APW17
    /// (`s19xp-modern-psu-selection.asm` / `s19jxp-modern-psu-selection.asm`).
    pub const fn psu_dialect(&self) -> Bm1366XpPsuDialect {
        match self.bin {
            Bm1366XpBin::Xp => Bm1366XpPsuDialect::XpApw12Modern,
            Bm1366XpBin::Jxp => Bm1366XpPsuDialect::JxpApw17Modern,
        }
    }

    /// Resolve a FRESHLY MEASURED PSU hardware version against this bin's
    /// fixed dialect. The admitted sets are the runtime law's exactly:
    /// APW12 modern 0x75..=0x77 for XP, APW17 modern 0xc1 for jXP; every
    /// other version (including the sibling dialect's versions, 0xc2, and
    /// the stock topol's older APW12 rosters such as 0x71..0x73/0x78)
    /// refuses. Selection by itself issues nothing: voltage, watchdog and
    /// heartbeat commands stay owned by the retained HAL PSU service.
    pub fn select_measured_psu_version(
        &self,
        version: u8,
    ) -> Result<Bm1366XpPsuDialect, PsuDialectError> {
        let dialect = self.psu_dialect();
        match (self.bin, version) {
            (Bm1366XpBin::Xp, 0x75..=0x77) => Ok(Bm1366XpPsuDialect::XpApw12Modern),
            (Bm1366XpBin::Jxp, 0xc1) => Ok(Bm1366XpPsuDialect::JxpApw17Modern),
            _ => Err(PsuDialectError::MeasuredVersionNotAdmitted { dialect, version }),
        }
    }

    /// The dispatch-admitted platform-table row for this bin. The row and
    /// this profile must agree on geometry (110/3); the join is pinned by
    /// tests in this module.
    pub fn dispatch_platform(
        &self,
    ) -> &'static crate::bm1366_serial_platform::Bm1366SerialPlatformProfile {
        crate::bm1366_serial_platform::bm1366_dispatch_admitted_serial_platform(self.board_target)
            .expect("XP-pair profile board targets are dispatch-admitted rows")
    }

    /// DCENT native target-frequency software policy per bin (MHz). These
    /// bounds are conservative software policy around the stock levels.json
    /// upper levels (XP 485, jXP 515), NOT electrical qualification; the
    /// cold-start ramp itself begins at 100 MHz and advances at most
    /// 6 MHz/100 ms regardless of the target (DCENT policy bounding the
    /// held 6.25 MHz/100 ms transition). Default target for both: 400.
    pub const fn target_mhz_bounds(&self) -> (u16, u16) {
        match self.bin {
            Bm1366XpBin::Xp => (400, 485),
            Bm1366XpBin::Jxp => (300, 515),
        }
    }

    /// Desk-completable cold-start prefix per the retained modern owner:
    /// cooling custody first, then the measured-PSU-gated rail command,
    /// then reset release (the modern lifecycle is checked cut-first /
    /// reset-second — `AmlogicPsuCommitAuthority::reset_after_cut == true`
    /// for both XP profiles, unlike S19k's reset-before-cut), then exact
    /// per-chain enumeration, and only then all-chain work.
    /// `Quiesced` / `SafeOffVerified` are intentionally absent: their
    /// admission is physical-proof-gated.
    pub fn desk_cold_start_prefix(&self) -> [ColdInitStage; 5] {
        let _ = self; // uniform order across the pair; PSU dialect differs per bin
        [
            ColdInitStage::CoolingAdmitted,
            ColdInitStage::RailEnergized,
            ColdInitStage::ResetReleased,
            ColdInitStage::ChainsInitialized,
            ColdInitStage::WorkEnabled,
        ]
    }
}

/// Board_target-scoped GPIO437 polarity evidence state for the XP pair.
/// Both resolved bins currently share one variant; the enum exists so a
/// future sibling (BHB56806/56807-class) cannot silently inherit the
/// mapping without its own factory-chain trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1366XpPowerPolarity {
    /// S19 XP and S19j XP production factory chain (root ; R14
    /// model->profile->PSU-controller trace; HAL `psu_is_active_low`):
    /// software mapping raw 0 = ON, raw 1 = OFF. Not a rail measurement.
    Am3MappedZeroOnOneOff,
}

/// Per-model PSU dialect for the XP pair. The two variants are distinct
/// wire dialects on the retained management bus; they must never be merged
/// and neither resolves the other's versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1366XpPsuDialect {
    /// S19 XP: modern APW12 (APW121215). Measured versions 0x75..=0x77.
    XpApw12Modern,
    /// S19j XP: modern APW17 (APW171215). Measured version 0xc1 only;
    /// PSU c2 (BHB56807 v[194]) is NOT inferred from c1.
    JxpApw17Modern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsuDialectError {
    /// The measured version is not admitted for the bin's dialect. This
    /// covers both wrong-dialect frames (XP bin seeing 0xc1, jXP bin seeing
    /// 0x75..0x77) and unknown/older versions (0xc2, 0x71..0x73, 0x78, ...).
    MeasuredVersionNotAdmitted {
        dialect: Bm1366XpPsuDialect,
        version: u8,
    },
}

// ---------------------------------------------------------------------------
// Per-chain init sequencing (retained owner: serial_mining::bm1366_xp_native).
// ---------------------------------------------------------------------------

/// The exact per-chain initialization steps of the retained BM1366 XP
/// initializer (`dcentrald/src/serial_mining/bm1366_xp_native.rs`, held
/// ESP-Miner `components/asic/bm1366.c:166..252`, explicitly annotated
/// S19XP stock dump). The listed order is the composition contract the
/// runtime owner implements; this module only pins it as data so tests can
/// prove the S19k program never leaks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1366XpChainInitStep {
    /// Three version-mask broadcasts (0xa4 = 0x9000_ffff, 5 ms apart).
    VersionMaskBroadcasts,
    /// Complete cold census: the full unassigned-zero 110-chip window MUST
    /// be observed; a partial census refuses before any mutation.
    ColdCensusExact110,
    /// A8 / 18 broadcasts then chain-inactive burst.
    BroadcastInactive,
    /// SetAddress ladder over the interval-2 addresses 0,2,..,218.
    AddressLadder,
    /// Core configuration (0x3c pair) + ticket mask 256 (0x14 = 0xff)
    /// + IO/analog mux (0x54/0x58) broadcasts.
    CoreConfigTicketIoMux,
    /// Single-chip 0x2c write, then the per-chip 0xa8/0x18/0x3c walk over
    /// all 110 assigned addresses.
    PerChipConfiguration,
    /// PLL transition to target via the <=6 MHz/100 ms ramp from 100 MHz
    /// (DCENT policy bounding the held 6.25 MHz/100 ms step).
    PllRampToTarget,
    /// HCN 0x10 = 0x151c work configuration (NOT the S19k 0x115a).
    HcnWorkConfig,
    /// Fresh assigned census: all 110 chips must answer on their assigned
    /// addresses before the chain joins work distribution.
    AssignedCensusExact110,
}

/// The retained XP per-chain init order.
pub const CHAIN_INIT_SEQUENCE: [Bm1366XpChainInitStep; 9] = [
    Bm1366XpChainInitStep::VersionMaskBroadcasts,
    Bm1366XpChainInitStep::ColdCensusExact110,
    Bm1366XpChainInitStep::BroadcastInactive,
    Bm1366XpChainInitStep::AddressLadder,
    Bm1366XpChainInitStep::CoreConfigTicketIoMux,
    Bm1366XpChainInitStep::PerChipConfiguration,
    Bm1366XpChainInitStep::PllRampToTarget,
    Bm1366XpChainInitStep::HcnWorkConfig,
    Bm1366XpChainInitStep::AssignedCensusExact110,
];

/// The XP-pair cold UART rate. The held initializer explicitly postpones
/// baud changes to a separate function, so command/work/RX stay at 115200;
/// the S19k 3 Mbaud pair is never inherited.
pub const BM1366_XP_COLD_BAUD: u32 = 115_200;

/// HCN register value of the XP program (held S19XP dump, via
/// `serial_mining::bm1366_xp_native`; PTY-replay-pinned literal).
pub const BM1366_XP_HCN_REGISTER_VALUE: u32 = 0x0000_151c;

/// The S19k HCN value kept here ONLY as a refusal contrast: the XP program
/// must never emit it.
pub const S19K_HCN_REGISTER_VALUE: u32 = 0x0000_115a;

/// Ticket-mask register value for difficulty 256 (register 0x14, plain
/// difficulty-1 encoding = 0xff; `TICKET_MASK_256` in the retained owner).
pub const BM1366_XP_TICKET_MASK_256_REGISTER_VALUE: u32 = 0x0000_00ff;

/// The S19k per-UART population kept here ONLY as a refusal contrast: a
/// 77-chip observation must never authorize an XP bin (and vice versa).
pub const S19K_EXPECTED_CHIPS_PER_UART: u16 = 77;

// ---------------------------------------------------------------------------
// Population admission: 110 exact per populated chain; partials refuse.
// ---------------------------------------------------------------------------

/// One chain's fresh full address-window observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPopulation {
    /// Physical chain slot 0..3 (AM3 UART slot, ttyS3=0 / ttyS2=1 / ttyS1=2).
    pub chain: u8,
    /// Freshly observed unassigned-zero address-window population. This is
    /// a runtime admission datum, not a stock nameplate.
    pub observed_chips: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopulationAdmissionError {
    /// No populated chain was observed (also: the full-unit manifest form
    /// was called without all three chains).
    EmptyUnit,
    /// Chain slot outside 0..3.
    ChainOutOfRange,
    /// The same physical slot was reported twice.
    DuplicateChain,
    /// Off-by-one (or any non-exact) population on a chain — including a
    /// 77-chip S19k observation offered to an XP bin.
    PopulationMismatch {
        chain: u8,
        observed: u16,
        expected: u16,
    },
}

/// An admitted unit: exact per-chain populations for one XP-pair bin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedBm1366XpUnit {
    pub profile: Bm1366XpBoardProfile,
    /// Populated chain slots, ascending, 1..=3 entries.
    pub populated_chains: [u8; 3],
    /// Number of valid entries in `populated_chains`.
    pub populated_count: usize,
}

/// Admit a fresh unit population against a bin's exact 110-chip geometry.
/// Physical subsets (one or two populated chains) are admissible — identity
/// never requires all three slots — but EVERY populated chain must report
/// the exact 110; 109, 111, and S19k's 77 all refuse.
pub fn admit_unit_population(
    profile: Bm1366XpBoardProfile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1366XpUnit, PopulationAdmissionError> {
    if populations.is_empty() {
        return Err(PopulationAdmissionError::EmptyUnit);
    }
    let mut populated_chains = [0u8; 3];
    let mut populated_count = 0usize;
    for population in populations {
        if population.chain >= BM1366_XP_CHAINS_PER_UNIT {
            return Err(PopulationAdmissionError::ChainOutOfRange);
        }
        if populated_chains[..populated_count]
            .iter()
            .any(|prior| *prior == population.chain)
        {
            return Err(PopulationAdmissionError::DuplicateChain);
        }
        if population.observed_chips != profile.chips_per_chain {
            return Err(PopulationAdmissionError::PopulationMismatch {
                chain: population.chain,
                observed: population.observed_chips,
                expected: profile.chips_per_chain,
            });
        }
        populated_chains[populated_count] = population.chain;
        populated_count += 1;
    }
    Ok(AdmittedBm1366XpUnit {
        profile,
        populated_chains,
        populated_count,
    })
}

/// Stricter full-unit manifest: exactly all three chains, each exact 110.
pub fn admit_full_unit_population(
    profile: Bm1366XpBoardProfile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1366XpUnit, PopulationAdmissionError> {
    let unit = admit_unit_population(profile, populations)?;
    if unit.populated_count != usize::from(BM1366_XP_CHAINS_PER_UNIT) {
        return Err(PopulationAdmissionError::EmptyUnit);
    }
    Ok(unit)
}

// ---------------------------------------------------------------------------
// All-chain work distribution planning.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionError {
    /// The requested chain was never admitted (unpopulated slots receive
    /// no work and must not be dispatched).
    ChainNotAdmitted,
    /// A coverage receipt names a chain outside the admitted unit.
    ReceiptForeignChain,
    /// A coverage receipt was stamped by a superseded (stale) session
    /// epoch; only the live epoch's receipts count.
    ReceiptStaleEpoch { receipt_epoch: u64, live_epoch: u64 },
    /// Not every admitted chain received the work item exactly once.
    CoverageIncomplete,
}

/// One per-chain work assignment. `work_id` is the ASIC job id (the job-id
/// increment and BM1366 midstate <<2 wire shift stay owned by the existing
/// work dispatcher and driver).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainWorkAssignment {
    pub chain: u8,
    pub work_id: u16,
}

/// Plan one work item onto EVERY admitted chain. "All-chain dispatch" is
/// the load-bearing property: a full unit mines only when all populated
/// chains receive the item (R12 acceptance: positive multi-chain work).
pub fn distribute_work_to_all_chains(
    unit: &AdmittedBm1366XpUnit,
    work_id: u16,
) -> Result<Vec<ChainWorkAssignment>, DistributionError> {
    Ok(unit.populated_chains[..unit.populated_count]
        .iter()
        .map(|&chain| ChainWorkAssignment { chain, work_id })
        .collect())
}

/// Address one admitted chain only; unpopulated slots refuse.
pub fn distribute_work_to_chain(
    unit: &AdmittedBm1366XpUnit,
    chain: u8,
    work_id: u16,
) -> Result<ChainWorkAssignment, DistributionError> {
    if !unit.populated_chains[..unit.populated_count].contains(&chain) {
        return Err(DistributionError::ChainNotAdmitted);
    }
    Ok(ChainWorkAssignment { chain, work_id })
}

/// Verify a session ledger: every admitted chain received `work_id` exactly
/// once, and no receipt names a foreign (unadmitted) chain. Epoch-blind —
/// the session-scoped form [`session_coverage_complete`] adds staleness.
pub fn coverage_complete(
    unit: &AdmittedBm1366XpUnit,
    work_id: u16,
    receipts: &[ChainWorkAssignment],
) -> Result<(), DistributionError> {
    for receipt in receipts {
        if !unit.populated_chains[..unit.populated_count].contains(&receipt.chain) {
            return Err(DistributionError::ReceiptForeignChain);
        }
    }
    for &chain in &unit.populated_chains[..unit.populated_count] {
        let hits = receipts
            .iter()
            .filter(|receipt| receipt.chain == chain && receipt.work_id == work_id)
            .count();
        if hits != 1 {
            return Err(DistributionError::CoverageIncomplete);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Session composition: staged cold-start, mid-init cancellation, stale
// epochs. Pure state only — the wire executor stays in its retained owner.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Advance was not to the immediate next stage of the cold-start prefix.
    InvalidAdvance {
        from: ColdInitStage,
        to: ColdInitStage,
    },
    /// Work was planned before the session reached `WorkEnabled`.
    WorkNotEnabled { stage: ColdInitStage },
    /// The session was cancelled (possibly mid-init); it admits nothing
    /// further and can never be resumed.
    SessionCancelled { cancelled_at: ColdInitStage },
    /// A replacement session can only follow a CANCELLED session; a live
    /// (or completed) session has no successor until it is cancelled.
    ReplacementRequiresCancelledSession,
}

/// A per-chip nonce receipt stamped with the session epoch that planned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionWorkReceipt {
    pub chain: u8,
    pub work_id: u16,
    pub epoch: u64,
}

/// One staged mining session over an admitted XP-pair unit. The stage
/// ladder is [`Bm1366XpBoardProfile::desk_cold_start_prefix`]; `cancel` is
/// legal from ANY stage (mid-init included), is terminal, and a replacement
/// session always advances the epoch so stale receipts cannot validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1366XpWorkSession {
    unit: AdmittedBm1366XpUnit,
    epoch: u64,
    stage: ColdInitStage,
    cancelled_at: Option<ColdInitStage>,
}

impl Bm1366XpWorkSession {
    /// Begin the first session for a unit (epoch 1) at the first prefix
    /// stage.
    pub fn begin(unit: AdmittedBm1366XpUnit) -> Self {
        Self {
            unit,
            epoch: 1,
            stage: ColdInitStage::CoolingAdmitted,
            cancelled_at: None,
        }
    }

    /// Begin a replacement session after a cancelled one. The replacement
    /// inherits the unit and advances the epoch; cancelling is terminal for
    /// the cancelled session but does not lock the hardware forever.
    pub fn begin_after(previous: &Self) -> Result<Self, SessionError> {
        if previous.cancelled_at.is_none() {
            return Err(SessionError::ReplacementRequiresCancelledSession);
        }
        Ok(Self {
            unit: previous.unit,
            epoch: previous.epoch + 1,
            stage: ColdInitStage::CoolingAdmitted,
            cancelled_at: None,
        })
    }

    pub fn unit(&self) -> &AdmittedBm1366XpUnit {
        &self.unit
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn stage(&self) -> ColdInitStage {
        self.stage
    }

    pub fn cancelled_at(&self) -> Option<ColdInitStage> {
        self.cancelled_at
    }

    /// Advance to the immediate next stage of the prefix. Refuses skips,
    /// regressions, and any advance after cancellation.
    pub fn advance_to(&mut self, to: ColdInitStage) -> Result<(), SessionError> {
        if let Some(cancelled_at) = self.cancelled_at {
            return Err(SessionError::SessionCancelled { cancelled_at });
        }
        let ladder = self.unit.profile.desk_cold_start_prefix();
        let from_index = ladder
            .iter()
            .position(|stage| *stage == self.stage)
            .expect("session stage always starts on the prefix");
        let to_index =
            ladder
                .iter()
                .position(|stage| *stage == to)
                .ok_or(SessionError::InvalidAdvance {
                    from: self.stage,
                    to,
                })?;
        if to_index != from_index + 1 {
            return Err(SessionError::InvalidAdvance {
                from: self.stage,
                to,
            });
        }
        self.stage = to;
        Ok(())
    }

    /// Cancel from any stage — mid-init included. Terminal: every later
    /// operation refuses. This is the pure fault-injection model of the
    /// wire owner's terminal revocation (`terminal.revoke()`), which stops
    /// further serial writes once the session is torn down.
    pub fn cancel(&mut self) {
        if self.cancelled_at.is_none() {
            self.cancelled_at = Some(self.stage);
        }
    }

    /// Plan one work item onto every admitted chain. Refuses unless the
    /// session reached `WorkEnabled` and was never cancelled.
    pub fn plan_work(&self, work_id: u16) -> Result<Vec<ChainWorkAssignment>, SessionError> {
        if let Some(cancelled_at) = self.cancelled_at {
            return Err(SessionError::SessionCancelled { cancelled_at });
        }
        if self.stage != ColdInitStage::WorkEnabled {
            return Err(SessionError::WorkNotEnabled { stage: self.stage });
        }
        distribute_work_to_all_chains(&self.unit, work_id)
            .map_err(|_| SessionError::WorkNotEnabled { stage: self.stage })
    }
}

/// Session-scoped coverage: every admitted chain received `work_id` exactly
/// once, no receipt names a foreign chain, and every receipt carries the
/// LIVE epoch — receipts stamped by a cancelled/superseded session are
/// stale and refuse.
pub fn session_coverage_complete(
    session: &Bm1366XpWorkSession,
    work_id: u16,
    receipts: &[SessionWorkReceipt],
) -> Result<(), DistributionError> {
    let live_epoch = session.epoch();
    for receipt in receipts {
        if receipt.epoch != live_epoch {
            return Err(DistributionError::ReceiptStaleEpoch {
                receipt_epoch: receipt.epoch,
                live_epoch,
            });
        }
    }
    let plain: Vec<ChainWorkAssignment> = receipts
        .iter()
        .map(|receipt| ChainWorkAssignment {
            chain: receipt.chain,
            work_id: receipt.work_id,
        })
        .collect();
    coverage_complete(session.unit(), work_id, &plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_full_unit(profile: Bm1366XpBoardProfile) -> Vec<ChainPopulation> {
        (0..3)
            .map(|chain| ChainPopulation {
                chain,
                observed_chips: profile.chips_per_chain,
            })
            .collect()
    }

    #[test]
    fn exact_per_bin_geometry_is_pinned_and_the_pair_stays_two_bins() {
        let expected = [
            (
                Bm1366XpBoardProfile::XP,
                "am3-s19xp",
                110u16,
                11u8,
                10u8,
                330u16,
            ),
            (Bm1366XpBoardProfile::JXP, "am3-s19jxp", 110, 11, 10, 330),
        ];
        for (profile, target, chips, domains, per_domain, per_unit) in expected {
            assert_eq!(profile.board_target, target);
            assert_eq!(profile.chips_per_chain, chips);
            assert_eq!(
                (profile.domains_per_board * profile.chips_per_domain) as u16,
                chips
            );
            assert_eq!(profile.chips_per_unit(), per_unit);
            assert_eq!(
                Bm1366XpBoardProfile::for_board_target(target),
                Some(profile)
            );
        }
        // Exactly two bins; S19k and the S21 family are not XP bins.
        assert_eq!(Bm1366XpBoardProfile::ALL.len(), 2);
        assert_eq!(Bm1366XpBoardProfile::for_board_target("am3-s19k"), None);
        assert_eq!(Bm1366XpBoardProfile::for_board_target("am3-s21xp"), None);
        assert_eq!(
            Bm1366XpBoardProfile::for_board_target("am3-s19xp-hydro"),
            None
        );
    }

    #[test]
    fn factory_names_select_their_exact_bin_and_never_a_sibling() {
        assert_eq!(
            Bm1366XpBoardProfile::for_board_name("BHB56801"),
            Some(Bm1366XpBoardProfile::XP)
        );
        assert_eq!(
            Bm1366XpBoardProfile::for_board_name("BHB56802"),
            Some(Bm1366XpBoardProfile::XP)
        );
        assert_eq!(
            Bm1366XpBoardProfile::for_board_name("BHB56804"),
            Some(Bm1366XpBoardProfile::JXP)
        );
        // Unknown siblings and foreign families select nothing: BHB56806
        // (XP 110/chain, no runtime identity fixture), BHB56807 (jXP
        // sibling, APW17 v[194] c2 NOT inferred), the 99/70 XP-merge
        // machines, and the S19k BHB569xx family.
        for name in [
            "BHB56806", "BHB56807", "BHB56601", "BHB56701", "BHB56901", "BHB56902", "BHB56903",
        ] {
            assert_eq!(Bm1366XpBoardProfile::for_board_name(name), None, "{name}");
        }
    }

    #[test]
    fn population_admission_requires_exact_110_and_refuses_partials_and_s19k() {
        for profile in Bm1366XpBoardProfile::ALL {
            admit_full_unit_population(profile, &exact_full_unit(profile))
                .expect("exact full 3x110 unit");
            admit_unit_population(profile, &exact_full_unit(profile)).expect("exact full unit");

            // Physical subsets stay admissible at exact per-chain counts.
            admit_unit_population(
                profile,
                &[ChainPopulation {
                    chain: 1,
                    observed_chips: profile.chips_per_chain,
                }],
            )
            .expect("single exact chain");

            // Off-by-one AND S19k's 77 refuse on every chain slot.
            for drifted in [
                profile.chips_per_chain - 1,
                profile.chips_per_chain + 1,
                S19K_EXPECTED_CHIPS_PER_UART,
            ] {
                for chain in 0..3u8 {
                    assert_eq!(
                        admit_unit_population(
                            profile,
                            &[ChainPopulation {
                                chain,
                                observed_chips: drifted,
                            }]
                        ),
                        Err(PopulationAdmissionError::PopulationMismatch {
                            chain,
                            observed: drifted,
                            expected: profile.chips_per_chain,
                        }),
                        "{}/chain population {drifted} must refuse",
                        profile.board_target
                    );
                }
            }

            // Empty, duplicate and out-of-range refuse.
            assert_eq!(
                admit_unit_population(profile, &[]),
                Err(PopulationAdmissionError::EmptyUnit)
            );
            let dup = [
                ChainPopulation {
                    chain: 0,
                    observed_chips: profile.chips_per_chain,
                },
                ChainPopulation {
                    chain: 0,
                    observed_chips: profile.chips_per_chain,
                },
            ];
            assert_eq!(
                admit_unit_population(profile, &dup),
                Err(PopulationAdmissionError::DuplicateChain)
            );
            assert_eq!(
                admit_unit_population(
                    profile,
                    &[ChainPopulation {
                        chain: 3,
                        observed_chips: profile.chips_per_chain,
                    }]
                ),
                Err(PopulationAdmissionError::ChainOutOfRange)
            );

            // Full-unit manifest refuses a missing chain (partial unit).
            let two: Vec<ChainPopulation> =
                exact_full_unit(profile).iter().take(2).copied().collect();
            assert_eq!(
                admit_full_unit_population(profile, &two),
                Err(PopulationAdmissionError::EmptyUnit)
            );
        }
    }

    #[test]
    fn measured_psu_dialect_law_never_merges_the_pair() {
        // XP: APW12 modern 0x75..=0x77 only.
        for version in [0x75u8, 0x76, 0x77] {
            assert_eq!(
                Bm1366XpBoardProfile::XP.select_measured_psu_version(version),
                Ok(Bm1366XpPsuDialect::XpApw12Modern),
                "XP measured 0x{version:02x}"
            );
        }
        // jXP: APW17 modern 0xc1 only.
        assert_eq!(
            Bm1366XpBoardProfile::JXP.select_measured_psu_version(0xc1),
            Ok(Bm1366XpPsuDialect::JxpApw17Modern)
        );
        // Wrong-dialect frames refuse BOTH ways, and unknown/older versions
        // refuse (0xc2 is the not-inferred sibling; 0x71..0x73/0x78 are the
        // stock topol's older APW12 rosters; 0x00 never selected anything).
        for (profile, version) in [
            (Bm1366XpBoardProfile::XP, 0xc1u8),
            (Bm1366XpBoardProfile::XP, 0xc2),
            (Bm1366XpBoardProfile::XP, 0x71),
            (Bm1366XpBoardProfile::XP, 0x72),
            (Bm1366XpBoardProfile::XP, 0x73),
            (Bm1366XpBoardProfile::XP, 0x78),
            (Bm1366XpBoardProfile::XP, 0x00),
            (Bm1366XpBoardProfile::JXP, 0x75),
            (Bm1366XpBoardProfile::JXP, 0x76),
            (Bm1366XpBoardProfile::JXP, 0x77),
            (Bm1366XpBoardProfile::JXP, 0xc2),
            (Bm1366XpBoardProfile::JXP, 0x00),
        ] {
            assert_eq!(
                profile.select_measured_psu_version(version),
                Err(PsuDialectError::MeasuredVersionNotAdmitted {
                    dialect: profile.psu_dialect(),
                    version,
                }),
                "{:?} measured 0x{version:02x} must refuse",
                profile.bin
            );
        }
        // The dialects themselves never compare equal: the pair is not one
        // profile with two version lists.
        assert_ne!(
            Bm1366XpPsuDialect::XpApw12Modern,
            Bm1366XpPsuDialect::JxpApw17Modern
        );
    }

    #[test]
    fn distribution_and_session_coverage_refuse_gaps_foreign_and_stale() {
        for profile in Bm1366XpBoardProfile::ALL {
            let unit = admit_full_unit_population(profile, &exact_full_unit(profile)).unwrap();
            let plan = distribute_work_to_all_chains(&unit, 7).unwrap();
            assert_eq!(
                plan,
                vec![
                    ChainWorkAssignment {
                        chain: 0,
                        work_id: 7
                    },
                    ChainWorkAssignment {
                        chain: 1,
                        work_id: 7
                    },
                    ChainWorkAssignment {
                        chain: 2,
                        work_id: 7
                    },
                ]
            );
            coverage_complete(&unit, 7, &plan).expect("full coverage");
            assert_eq!(
                coverage_complete(&unit, 7, &plan[..2]),
                Err(DistributionError::CoverageIncomplete)
            );
            assert_eq!(
                coverage_complete(
                    &unit,
                    7,
                    &[ChainWorkAssignment {
                        chain: 3,
                        work_id: 7
                    }]
                ),
                Err(DistributionError::ReceiptForeignChain)
            );

            // Single-chain unit dispatches to its own slot only.
            let single = admit_unit_population(
                profile,
                &[ChainPopulation {
                    chain: 2,
                    observed_chips: profile.chips_per_chain,
                }],
            )
            .unwrap();
            assert_eq!(
                distribute_work_to_all_chains(&single, 9).unwrap(),
                vec![ChainWorkAssignment {
                    chain: 2,
                    work_id: 9
                }]
            );
            assert_eq!(
                distribute_work_to_chain(&single, 0, 9),
                Err(DistributionError::ChainNotAdmitted)
            );
        }
    }

    #[test]
    fn session_stage_ladder_cancel_and_stale_epochs_refuse() {
        let profile = Bm1366XpBoardProfile::XP;
        let unit = admit_full_unit_population(profile, &exact_full_unit(profile)).unwrap();

        // Work before init completes refuses.
        let mut session = Bm1366XpWorkSession::begin(unit);
        assert_eq!(
            session.plan_work(1),
            Err(SessionError::WorkNotEnabled {
                stage: ColdInitStage::CoolingAdmitted
            })
        );
        // Skip and regression refuse; the exact ladder advances (begin()
        // starts ON the first stage, so the loop advances to the rest).
        assert_eq!(
            session.advance_to(ColdInitStage::ChainsInitialized),
            Err(SessionError::InvalidAdvance {
                from: ColdInitStage::CoolingAdmitted,
                to: ColdInitStage::ChainsInitialized,
            })
        );
        for stage in profile.desk_cold_start_prefix().iter().skip(1) {
            session.advance_to(*stage).expect("ladder advance");
        }
        let plan = session.plan_work(0x2a).expect("work after init");
        assert_eq!(plan.len(), 3);

        // Cancel at WorkEnabled is terminal.
        session.cancel();
        assert_eq!(
            session.plan_work(0x2b),
            Err(SessionError::SessionCancelled {
                cancelled_at: ColdInitStage::WorkEnabled
            })
        );
        assert!(session.advance_to(ColdInitStage::WorkEnabled).is_err());

        // Mid-init cancellation: a fresh session cancelled during
        // ChainsInitialized can never plan or advance.
        let mut mid = Bm1366XpWorkSession::begin_after(&session).expect("replacement session");
        assert_eq!(mid.epoch(), 2);
        mid.advance_to(ColdInitStage::RailEnergized).unwrap();
        mid.advance_to(ColdInitStage::ResetReleased).unwrap();
        mid.advance_to(ColdInitStage::ChainsInitialized).unwrap();
        mid.cancel();
        assert_eq!(
            mid.plan_work(0x2a),
            Err(SessionError::SessionCancelled {
                cancelled_at: ColdInitStage::ChainsInitialized
            })
        );
        assert_eq!(
            mid.advance_to(ColdInitStage::WorkEnabled),
            Err(SessionError::SessionCancelled {
                cancelled_at: ColdInitStage::ChainsInitialized
            })
        );

        // Stale receipts: epoch-1 receipts never validate on the epoch-2
        // session, and live-epoch receipts do.
        let stale = SessionWorkReceipt {
            chain: 0,
            work_id: 7,
            epoch: 1,
        };
        assert_eq!(
            session_coverage_complete(&mid, 7, &[stale]),
            Err(DistributionError::ReceiptStaleEpoch {
                receipt_epoch: 1,
                live_epoch: 2,
            })
        );
        let live: Vec<SessionWorkReceipt> = (0..3)
            .map(|chain| SessionWorkReceipt {
                chain,
                work_id: 7,
                epoch: 2,
            })
            .collect();
        session_coverage_complete(&mid, 7, &live).expect("live-epoch coverage");

        // begin_after refuses a session that was never cancelled.
        let mut fresh = Bm1366XpWorkSession::begin(unit);
        assert_eq!(
            Bm1366XpWorkSession::begin_after(&fresh),
            Err(SessionError::ReplacementRequiresCancelledSession)
        );
        fresh.cancel();
        // Double-cancel keeps the FIRST cancellation point.
        fresh.cancel();
        assert_eq!(fresh.cancelled_at(), Some(ColdInitStage::CoolingAdmitted));
    }

    #[test]
    fn routes_polarity_prefix_and_platform_join_stay_bound_to_the_pair() {
        for profile in Bm1366XpBoardProfile::ALL {
            assert_eq!(profile.uart_routes(), &AM3_S19XP_UART_ROUTES);
            assert_eq!(
                profile.power_polarity(),
                Bm1366XpPowerPolarity::Am3MappedZeroOnOneOff
            );
            assert_eq!(
                profile.desk_cold_start_prefix(),
                [
                    ColdInitStage::CoolingAdmitted,
                    ColdInitStage::RailEnergized,
                    ColdInitStage::ResetReleased,
                    ColdInitStage::ChainsInitialized,
                    ColdInitStage::WorkEnabled,
                ]
            );
            // The prefix never contains terminal physical-proof stages.
            let prefix = profile.desk_cold_start_prefix();
            assert!(!prefix.contains(&ColdInitStage::SafeOffVerified));
            assert!(!prefix.contains(&ColdInitStage::Quiesced));

            // The dispatch-table join agrees on geometry and admission.
            let row = profile.dispatch_platform();
            assert_eq!(row.board_target, profile.board_target);
            assert!(row.dispatch_admitted);
            assert_eq!(
                u16::from(row.expected_chips_per_uart),
                profile.chips_per_chain
            );
            assert_eq!(
                u16::from(row.stock_chain_count),
                u16::from(BM1366_XP_CHAINS_PER_UNIT)
            );
        }
        // The S19k row keeps its own 77 and is a different platform row.
        let s19k =
            crate::bm1366_serial_platform::bm1366_dispatch_admitted_serial_platform("am3-s19k")
                .expect("s19k row stays admitted");
        assert_eq!(
            u16::from(s19k.expected_chips_per_uart),
            S19K_EXPECTED_CHIPS_PER_UART
        );
        assert_ne!(s19k.board_target, Bm1366XpBoardProfile::XP.board_target);
    }

    #[test]
    fn init_sequence_pins_the_xp_program_and_refuses_s19k_leakage() {
        assert_eq!(
            CHAIN_INIT_SEQUENCE,
            [
                Bm1366XpChainInitStep::VersionMaskBroadcasts,
                Bm1366XpChainInitStep::ColdCensusExact110,
                Bm1366XpChainInitStep::BroadcastInactive,
                Bm1366XpChainInitStep::AddressLadder,
                Bm1366XpChainInitStep::CoreConfigTicketIoMux,
                Bm1366XpChainInitStep::PerChipConfiguration,
                Bm1366XpChainInitStep::PllRampToTarget,
                Bm1366XpChainInitStep::HcnWorkConfig,
                Bm1366XpChainInitStep::AssignedCensusExact110,
            ]
        );
        // Both censuses are exact-110 gates inside the sequence.
        assert!(CHAIN_INIT_SEQUENCE.contains(&Bm1366XpChainInitStep::ColdCensusExact110));
        assert!(CHAIN_INIT_SEQUENCE.contains(&Bm1366XpChainInitStep::AssignedCensusExact110));
        // The XP HCN differs from the S19k HCN, and the cold baud stays at
        // the retained 115200 (the S19k 3 Mbaud pair is never inherited).
        assert_ne!(BM1366_XP_HCN_REGISTER_VALUE, S19K_HCN_REGISTER_VALUE);
        assert_eq!(BM1366_XP_HCN_REGISTER_VALUE, 0x151c);
        assert_eq!(S19K_HCN_REGISTER_VALUE, 0x115a);
        assert_eq!(BM1366_XP_COLD_BAUD, 115_200);
        assert_ne!(BM1366_XP_COLD_BAUD, 3_000_000);
        assert_eq!(BM1366_XP_TICKET_MASK_256_REGISTER_VALUE, 0xff);

        // Frequency policy: the DCENT default 400 resolves exactly for both
        // bins and sits inside both bounds; each bin admits its own stock
        // upper level (XP 485, jXP 515); XP refuses the jXP-only 515; the
        // ramp start stays below every bound.
        for profile in Bm1366XpBoardProfile::ALL {
            let (low, high) = profile.target_mhz_bounds();
            let (_, actual) = crate::bm1366_pll_reg_and_actual(400);
            assert_eq!(actual, 400, "400 MHz must resolve exactly");
            assert!((low..=high).contains(&400));
            assert!(100 < low, "ramp starts below the target bounds");
        }
        assert_eq!(Bm1366XpBoardProfile::XP.target_mhz_bounds(), (400, 485));
        assert_eq!(Bm1366XpBoardProfile::JXP.target_mhz_bounds(), (300, 515));
        // The bin-exact stock upper levels differ: 485 (XP levels.json) and
        // 515 (jXP levels.json). XP's policy refuses 515; jXP's admits it.
        let (xp_low, xp_high) = Bm1366XpBoardProfile::XP.target_mhz_bounds();
        let (jxp_low, jxp_high) = Bm1366XpBoardProfile::JXP.target_mhz_bounds();
        assert!(!(xp_low..=xp_high).contains(&515));
        assert!((jxp_low..=jxp_high).contains(&515));
    }
}
