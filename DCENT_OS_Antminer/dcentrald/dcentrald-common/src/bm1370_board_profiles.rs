//! Exact per-bin BM1370 board profiles, full-unit population admission and
//! all-chain work distribution planning for the three resolved air-cooled
//! S21-family BM1370 bins (campaign `2026-09-07-antminer-beta-execution`,
//! lane R14). Pure and no-I/O: this module plans and refuses; it never opens
//! a UART, touches GPIO437, or grants electrical authority.
//!
//! Geometry (each bin is a distinct platform; none is an alias of another):
//!
//! | Bin | Board target | Factory boards | Domains x chips | Chips/chain | Chains | Chips/unit |
//! |---|---|---|---|---|---:|---:|
//! | S21 Pro | `am3-s21pro` | A3HB70601, A3HB70602 | 13 x 5 | 65 | 3 | 195 |
//! | S21+ | `amlogic-s21plus` | A3HB70701, A3HB70702, A3HB70703 | 11 x 5 | 55 | 3 | 165 |
//! | S21 XP | `am3-s21xp` | A3HB70501, A3HB70502, A3HB70503 | 13 x 7 | 91 | 3 | 273 |
//!
//! Citations per datum:
//! - Held bosminer model list
//!
//!   (16,854 bytes, SHA-256 `c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0`):
//!   S21 Pro / A3HB70601,A3HB70602 = 13 x 5 = 65; S21+ / A3HB70701 = 11 x 5 = 55;
//!   S21 XP / A3HB70501 = 13 x 7 = 91. "S21 Pro is 13x5=65 - distinct platform,
//!   not an alias" is pinned in the F02 tuple union
//!   (`evidence/f02/tuple-union-v1/tuples.json`, rows `R-am3-s21pro` /
//!   `E-S21plus` / `R-am3-s21xp`).
//! - Held S21 production bosminer
//!    (23,890,320
//!   bytes, SHA-256
//!   `64e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1`),
//!   via `evidence/r14/production-profile-checkpoint.md` +
//!   `evidence/r14/production-model-psu-selection.asm`: the S21 Pro model
//!   constructor `0x6f6870` selects chip profile `0x824ce0` with chip count
//!   65 (immediate at `0x825090`) and board names `A3HB70601/A3HB70602` at
//!   `0x198c098`; the S21 XP model constructor `0x6f9b88` selects `0x825c94`
//!   with chip count 91 (immediate at `0x8260a4`) and the executable name
//!   table **A3HB70501, A3HB70502, A3HB70503**. Both feed the actual voltage
//!   factory `0x8c7a10`, which with their profile byte `+0x188 = 1` selects
//!   `PsuAsVoltageController` (NoPic), never the separate PIC path.
//! - The S21+ 55-chip runtime layout is NOT yet traced in that production
//!   binary ("exact runtime layout still to trace", checkpoint board table);
//!   its A3HB707xx names come from the held model-list/companion metadata
//!   only. This module therefore carries the Plus bin as an exact
//!   evidence-backed *admission target* without a runtime route/power claim.
//! - Polarity (board_target-scoped, root  load-bearing rule,
//!   memories 2026-06-30 / 2026-09-07): exact `am3-s21` is GPIO437
//!   **0=ON, 1=OFF** by control-flow proof (`evidence/r13/production-psu.md`);
//!   exact S21 Pro/XP join the same 0=ON,1=OFF AM3 mapping through their
//!   production model->ASIC-profile->PSU-controller factory chain (R14,
//!   `production-model-psu-selection.asm`). S21+ has NO traced factory chain
//!   and inherits nothing: its polarity stays [`PowerPolarityJoin::Unproven`].
//!   These are software traces, not DMM rail measurements.
//! - Physical chip attribution stays unknown: the BM1370 nonce wire field
//!   carries a core/counter pair, not a chip address
//!   (`bm1370_work_geometry::bm1370_physical_chip_index` returns `None`).
//!   Chain-level attribution (which UART produced a share) is exact;
//!   per-chip autotuning is not required for chain-level accepted shares
//!   (findings.md row "S21 Pro/+/XP BM1370").

use crate::bm1370_work_geometry::WorkGeometryError;
use crate::s21_generation_admission::ColdInitStage;

/// BM1370 chip ID (driver `dcentrald-asic/src/drivers/bm1370.rs::CHIP_ID`).
pub const BM1370_CHIP_ID: u16 = 0x1370;

/// Every resolved air-cooled BM1370 full unit presents three hashboard chains.
pub const BM1370_CHAINS_PER_UNIT: u8 = 3;

/// Verified AM3 physical-slot UART routes for the bins whose AML registry
/// key3 controller descriptor is held (`evidence/r14/production-profile-checkpoint.md`,
/// "AML controller registry" section): physical slots 1/2/3 map to
/// ttyS3/ttyS2/ttyS1, replacing the obsolete Pro ttyS1/2/4 guess. The S21+
/// registry descriptor was never traced, so its routes stay `None` — not
/// inherited from a sibling board target.
pub const AM3_S21_UART_ROUTES: [&str; 3] = ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"];

/// Resolved air-cooled BM1370 board bins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1370BoardBin {
    /// Antminer S21 Pro.
    Pro,
    /// Antminer S21+ (distinct platform; never a Pro alias).
    Plus,
    /// Antminer S21 XP.
    Xp,
}

/// Exact per-bin profile. Geometry and names are evidence-backed; route,
/// PSU and polarity facets are scoped per the module citations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1370BoardProfile {
    pub bin: Bm1370BoardBin,
    /// Campaign board target string. S21+ uses the admission-contract name
    /// `amlogic-s21plus` (`s21_generation_admission::S21PLUS_AML`); it has no
    /// registered BoardDesc row yet (F02 tuple `E-S21plus`, lane RED).
    pub board_target: &'static str,
    /// Exact factory hashboard names that may select this bin. Format1
    /// plaintext EEPROM names decode through
    /// `dcentrald-api-types::deployed_eeprom` (bytes 1..16); serial, tuning
    /// and CRC stay unknown and are never fabricated.
    pub board_names: &'static [&'static str],
    pub domains_per_board: u8,
    pub chips_per_domain: u8,
    /// Exact full-chain ASIC population. An off-by-one observation refuses.
    pub chips_per_chain: u16,
}

impl Bm1370BoardProfile {
    /// S21 Pro: 13 domains x 5 = 65 chips per chain, 3 x 65 = 195 per unit.
    pub const PRO: Self = Self {
        bin: Bm1370BoardBin::Pro,
        board_target: "am3-s21pro",
        board_names: &["A3HB70601", "A3HB70602"],
        domains_per_board: 13,
        chips_per_domain: 5,
        chips_per_chain: 65,
    };

    /// S21+: 11 domains x 5 = 55 chips per chain, 3 x 55 = 165 per unit.
    /// Admission target only: no route, PSU or polarity claim (module doc).
    pub const PLUS: Self = Self {
        bin: Bm1370BoardBin::Plus,
        board_target: "amlogic-s21plus",
        board_names: &["A3HB70701", "A3HB70702", "A3HB70703"],
        domains_per_board: 11,
        chips_per_domain: 5,
        chips_per_chain: 55,
    };

    /// S21 XP: 13 domains x 7 = 91 chips per chain, 3 x 91 = 273 per unit.
    pub const XP: Self = Self {
        bin: Bm1370BoardBin::Xp,
        board_target: "am3-s21xp",
        board_names: &["A3HB70501", "A3HB70502", "A3HB70503"],
        domains_per_board: 13,
        chips_per_domain: 7,
        chips_per_chain: 91,
    };

    /// All resolved bins, Pro / Plus / XP order (65 / 55 / 91).
    pub const ALL: [Self; 3] = [Self::PRO, Self::PLUS, Self::XP];

    /// Exact profile for a campaign board target, else `None`.
    pub fn for_board_target(target: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.board_target == target)
    }

    /// Exact profile for a decoded factory board name, else `None`.
    /// A3HB70601 must never select XP91 and A3HB70701 must never inherit
    /// Pro65 (cross-model refusal is pinned by tests here and by
    /// `s21_native_identity::validate_bm1370_pages`).
    pub fn for_board_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.board_names.contains(&name))
    }

    /// Exact full-unit ASIC count at the bin geometry: 195 / 165 / 273.
    /// (Lead landing fix 2026-09-12: `u16::from` is not const-stable on this
    /// toolchain; the widening cast is identical for u8 -> u16.)
    pub const fn chips_per_unit(&self) -> u16 {
        self.chips_per_chain * (BM1370_CHAINS_PER_UNIT as u16)
    }

    /// Verified physical UART routes for the bins whose AML registry key3
    /// controller descriptor is held; `None` for the untraced S21+ bin.
    pub const fn uart_routes(&self) -> Option<&'static [&'static str; 3]> {
        match self.bin {
            Bm1370BoardBin::Pro | Bm1370BoardBin::Xp => Some(&AM3_S21_UART_ROUTES),
            Bm1370BoardBin::Plus => None,
        }
    }

    /// Board_target-scoped GPIO437 polarity evidence. Pro/XP return the
    /// joined AM3 software mapping (raw 0 = enable, raw 1 = disable) with
    /// their exact citations; Plus returns [`PowerPolarityJoin::Unproven`].
    /// Never construct an electrical command from the software mapping alone:
    /// it is not a DMM rail measurement, and terminal SafeOff admission still
    /// requires the physical proof path in
    /// `s21_generation_admission::verify_power_polarity`.
    pub const fn power_polarity_join(&self) -> PowerPolarityJoin {
        match self.bin {
            Bm1370BoardBin::Pro | Bm1370BoardBin::Xp => PowerPolarityJoin::Am3MappedZeroOnOneOff,
            Bm1370BoardBin::Plus => PowerPolarityJoin::Unproven,
        }
    }

    /// PSU selection scope. Pro/XP resolve a fresh measured hardware version
    /// to exactly one of the two traced production profiles (APW121215
    /// 0x75..0x77 or APW171215 0xc1; unknown versions cannot issue voltage,
    /// watchdog or heartbeat commands). Plus has no traced PSU profile.
    pub const fn psu_selection(&self) -> PsuSelectionScope {
        match self.bin {
            Bm1370BoardBin::Pro | Bm1370BoardBin::Xp => PsuSelectionScope::MeasuredAutoModern,
            Bm1370BoardBin::Plus => PsuSelectionScope::Unknown,
        }
    }

    /// Desk-completable cold-start prefix per the settled composition
    /// (`evidence/r13/cold-boot-composition.md` implementation order and the
    /// R14 native join): cooling custody first, then measured PSU version
    /// discovery and the rail command, then selected-population reset
    /// release, then exact per-chain enumeration, and only then all-chain
    /// work. `Quiesced` / `SafeOffVerified` are intentionally absent: their
    /// admission is physical-proof-gated via
    /// `s21_generation_admission::admit_cold_init_unwind`.
    pub fn desk_cold_start_prefix(&self) -> [ColdInitStage; 5] {
        let _ = self; // uniform order across bins; facets differ per psu_selection()
        [
            ColdInitStage::CoolingAdmitted,
            ColdInitStage::RailEnergized,
            ColdInitStage::ResetReleased,
            ColdInitStage::ChainsInitialized,
            ColdInitStage::WorkEnabled,
        ]
    }
}

/// Board_target-scoped GPIO437 polarity evidence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerPolarityJoin {
    /// Exact am3-s21 (R13 control-flow proof) and the S21 Pro/XP production
    /// model->ASIC-profile->PSU-controller factory chain (R14): software
    /// mapping raw 0 = ON, raw 1 = OFF. Not a rail measurement.
    Am3MappedZeroOnOneOff,
    /// No traced factory chain for this board target. S21+ lands here until
    /// its own chain is proven; it never inherits a sibling's mapping.
    Unproven,
}

/// PSU profile selection scope for a bin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsuSelectionScope {
    /// Fresh measured hardware version resolves to APW121215 (0x75..0x77) or
    /// APW171215 (0xc1) only; failed rediscovery clears authorization.
    MeasuredAutoModern,
    /// No traced PSU profile; nothing may be issued.
    Unknown,
}

// ---------------------------------------------------------------------------
// Population admission: 65 / 55 / 91 exact; off-by-one refuses.
// ---------------------------------------------------------------------------

/// One chain's fresh full GetAddress observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPopulation {
    /// Physical chain slot 0..3 (AM3 UART slot, ttyS3=0 / ttyS2=1 / ttyS1=2).
    pub chain: u8,
    /// Freshly observed unassigned-zero address-window population.
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
    /// Off-by-one (or any non-exact) population on a chain.
    PopulationMismatch {
        chain: u8,
        observed: u16,
        expected: u16,
    },
}

/// An admitted unit: exact per-chain populations for one bin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedBm1370Unit {
    pub profile: Bm1370BoardProfile,
    /// Populated chain slots, ascending, 1..=3 entries.
    pub populated_chains: [u8; 3],
    /// Number of valid entries in `populated_chains`.
    pub populated_count: usize,
}

/// Admit a fresh unit population against a bin's exact geometry. Physical
/// subsets (one or two populated chains) are admissible — identity never
/// requires all three slots — but EVERY populated chain must report the bin's
/// exact chip count; 64/66 on Pro, 54/56 on Plus, 90/92 on XP all refuse.
pub fn admit_unit_population(
    profile: Bm1370BoardProfile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1370Unit, PopulationAdmissionError> {
    if populations.is_empty() {
        return Err(PopulationAdmissionError::EmptyUnit);
    }
    let mut populated_chains = [0u8; 3];
    let mut populated_count = 0usize;
    for population in populations {
        if population.chain >= BM1370_CHAINS_PER_UNIT {
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
    Ok(AdmittedBm1370Unit {
        profile,
        populated_chains,
        populated_count,
    })
}

/// Stricter full-unit manifest: exactly all three chains, each exact.
pub fn admit_full_unit_population(
    profile: Bm1370BoardProfile,
    populations: &[ChainPopulation],
) -> Result<AdmittedBm1370Unit, PopulationAdmissionError> {
    let unit = admit_unit_population(profile, populations)?;
    if unit.populated_count != usize::from(BM1370_CHAINS_PER_UNIT) {
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
    /// Not every admitted chain received the work item exactly once.
    CoverageIncomplete,
}

/// One per-chain work assignment. `work_id` is the ASIC job id (the BM1370
/// job-id increment policy is owned by the existing work dispatcher).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainWorkAssignment {
    pub chain: u8,
    pub work_id: u16,
}

/// Plan one work item onto EVERY admitted chain. "All-chain dispatch" is the
/// load-bearing property: a full unit mines only when all populated chains
/// receive the item (findings.md: "every full-unit chain receives work").
pub fn distribute_work_to_all_chains(
    unit: &AdmittedBm1370Unit,
    work_id: u16,
) -> Result<Vec<ChainWorkAssignment>, DistributionError> {
    Ok(unit.populated_chains[..unit.populated_count]
        .iter()
        .map(|&chain| ChainWorkAssignment { chain, work_id })
        .collect())
}

/// Address one admitted chain only; unpopulated slots refuse.
pub fn distribute_work_to_chain(
    unit: &AdmittedBm1370Unit,
    chain: u8,
    work_id: u16,
) -> Result<ChainWorkAssignment, DistributionError> {
    if !unit.populated_chains[..unit.populated_count].contains(&chain) {
        return Err(DistributionError::ChainNotAdmitted);
    }
    Ok(ChainWorkAssignment { chain, work_id })
}

/// Verify a session ledger: every admitted chain received `work_id` exactly
/// once, and no receipt names a foreign (unadmitted) chain.
pub fn coverage_complete(
    unit: &AdmittedBm1370Unit,
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

/// Research helper for work-window assessment reuse: maps the bin to the
/// domain/chip factorization checked by
/// `bm1370_work_geometry::S21ProWorkResearchPlan::for_exact_topology`.
/// Only the captured S21 Pro plan (13 x 5) exists today; the other bins
/// return [`WorkGeometryError::UnsupportedTopology`] by design.
pub const fn pro_research_topology(
    profile: &Bm1370BoardProfile,
) -> Result<(u8, u8), WorkGeometryError> {
    match (profile.domains_per_board, profile.chips_per_domain) {
        (13, 5) => Ok((13, 5)),
        _ => Err(WorkGeometryError::UnsupportedTopology),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_per_bin_geometry_is_pinned() {
        let expected = [
            (
                Bm1370BoardProfile::PRO,
                "am3-s21pro",
                65u16,
                13u8,
                5u8,
                195u16,
            ),
            (Bm1370BoardProfile::PLUS, "amlogic-s21plus", 55, 11, 5, 165),
            (Bm1370BoardProfile::XP, "am3-s21xp", 91, 13, 7, 273),
        ];
        for (profile, target, chips, domains, per_domain, per_unit) in expected {
            assert_eq!(profile.board_target, target);
            assert_eq!(profile.chips_per_chain, chips);
            assert_eq!(
                (profile.domains_per_board * profile.chips_per_domain) as u16,
                chips
            );
            assert_eq!(profile.domains_per_board, domains);
            assert_eq!(profile.chips_per_domain, per_domain);
            assert_eq!(profile.chips_per_unit(), per_unit);
            assert_eq!(Bm1370BoardProfile::for_board_target(target), Some(profile));
        }
        // The 65/55/91 set is exactly these three bins.
        let counts: [u16; 3] = Bm1370BoardProfile::ALL.map(|p| p.chips_per_chain);
        assert_eq!(counts, [65, 55, 91]);
        assert_eq!(Bm1370BoardProfile::for_board_target("am3-s21"), None);
        assert_eq!(Bm1370BoardProfile::for_board_target("am3-s21pro+"), None);
    }

    #[test]
    fn factory_names_select_their_exact_bin_and_never_a_sibling() {
        assert_eq!(
            Bm1370BoardProfile::for_board_name("A3HB70601"),
            Some(Bm1370BoardProfile::PRO)
        );
        assert_eq!(
            Bm1370BoardProfile::for_board_name("A3HB70602"),
            Some(Bm1370BoardProfile::PRO)
        );
        for name in ["A3HB70701", "A3HB70702", "A3HB70703"] {
            assert_eq!(
                Bm1370BoardProfile::for_board_name(name),
                Some(Bm1370BoardProfile::PLUS)
            );
        }
        for name in ["A3HB70501", "A3HB70502", "A3HB70503"] {
            assert_eq!(
                Bm1370BoardProfile::for_board_name(name),
                Some(Bm1370BoardProfile::XP)
            );
        }
        // Cross-model refusals: a Plus name cannot be reinterpreted, and the
        // base-S21 BM1368 BHB68 family selects nothing here.
        for name in ["BHB68603", "BHB68606", "BHB56903", "A3HB70999"] {
            assert_eq!(Bm1370BoardProfile::for_board_name(name), None);
        }
    }

    #[test]
    fn population_admission_requires_exact_counts_and_refuses_off_by_one() {
        for profile in Bm1370BoardProfile::ALL {
            let full: Vec<ChainPopulation> = (0..3)
                .map(|chain| ChainPopulation {
                    chain,
                    observed_chips: profile.chips_per_chain,
                })
                .collect();
            admit_full_unit_population(profile, &full).expect("exact full unit");
            admit_unit_population(profile, &full).expect("exact full unit");

            // Physical subsets stay admissible at exact per-chain counts.
            admit_unit_population(
                profile,
                &[ChainPopulation {
                    chain: 2,
                    observed_chips: profile.chips_per_chain,
                }],
            )
            .expect("single exact chain");

            // Off-by-one refuses on every chain slot, both directions.
            for drifted in [profile.chips_per_chain - 1, profile.chips_per_chain + 1] {
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
                        "{} population {drifted} must refuse",
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
                    chain: 1,
                    observed_chips: profile.chips_per_chain,
                },
                ChainPopulation {
                    chain: 1,
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

            // Full-unit manifest refuses a missing chain.
            let two: Vec<ChainPopulation> = full.iter().take(2).copied().collect();
            assert_eq!(
                admit_full_unit_population(profile, &two),
                Err(PopulationAdmissionError::EmptyUnit)
            );

            // Cross-bin counts refuse: a 65-chain observation on Plus/XP and
            // a 55-chain observation on Pro/XP are population mismatches.
            for other in Bm1370BoardProfile::ALL {
                if other == profile {
                    continue;
                }
                assert!(matches!(
                    admit_unit_population(
                        profile,
                        &[ChainPopulation {
                            chain: 0,
                            observed_chips: other.chips_per_chain,
                        }]
                    ),
                    Err(PopulationAdmissionError::PopulationMismatch { .. })
                ));
            }
        }
    }

    #[test]
    fn all_chain_distribution_and_coverage_refuse_gaps_and_foreign_chains() {
        for profile in Bm1370BoardProfile::ALL {
            let full: Vec<ChainPopulation> = (0..3)
                .map(|chain| ChainPopulation {
                    chain,
                    observed_chips: profile.chips_per_chain,
                })
                .collect();
            let unit = admit_full_unit_population(profile, &full).unwrap();

            let plan = distribute_work_to_all_chains(&unit, 7).unwrap();
            assert_eq!(plan.len(), 3);
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

            // A missing chain breaks coverage; a foreign chain receipt refuses.
            assert_eq!(
                coverage_complete(&unit, 7, &plan[..2]),
                Err(DistributionError::CoverageIncomplete)
            );
            // A solo receipt from an ADMITTED chain is not foreign: coverage
            // fails because the other two admitted chains have no receipt
            // (exact-once coverage is per admitted chain).
            assert_eq!(
                coverage_complete(
                    &unit,
                    7,
                    &[ChainWorkAssignment {
                        chain: 2,
                        work_id: 7
                    }]
                ),
                Err(DistributionError::CoverageIncomplete)
            );
            // A receipt naming a chain OUTSIDE the admitted unit is foreign.
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

            // Single-chain unit: dispatch to its own slot only.
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
            distribute_work_to_chain(&single, 2, 9).expect("admitted slot");
            assert_eq!(
                distribute_work_to_chain(&single, 0, 9),
                Err(DistributionError::ChainNotAdmitted)
            );
            assert_eq!(
                distribute_work_to_chain(&single, 3, 9),
                Err(DistributionError::ChainNotAdmitted)
            );
        }
    }

    #[test]
    fn route_polarity_and_psu_scoping_never_leak_across_bins() {
        for profile in [Bm1370BoardProfile::PRO, Bm1370BoardProfile::XP] {
            assert_eq!(profile.uart_routes(), Some(&AM3_S21_UART_ROUTES));
            assert_eq!(
                profile.power_polarity_join(),
                PowerPolarityJoin::Am3MappedZeroOnOneOff
            );
            assert_eq!(
                profile.psu_selection(),
                PsuSelectionScope::MeasuredAutoModern
            );
        }
        // Plus inherits nothing: no routes, no polarity join, no PSU profile.
        let plus = Bm1370BoardProfile::PLUS;
        assert_eq!(plus.uart_routes(), None);
        assert_eq!(plus.power_polarity_join(), PowerPolarityJoin::Unproven);
        assert_eq!(plus.psu_selection(), PsuSelectionScope::Unknown);
    }

    #[test]
    fn cold_start_prefix_is_cooling_power_reset_chains_work() {
        for profile in Bm1370BoardProfile::ALL {
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
        }
        // Terminal stages stay excluded from the desk-completable prefix.
        let prefix = Bm1370BoardProfile::PRO.desk_cold_start_prefix();
        assert!(!prefix.contains(&ColdInitStage::SafeOffVerified));
        assert!(!prefix.contains(&ColdInitStage::Quiesced));
    }

    #[test]
    fn research_topology_is_pro_capture_only() {
        assert_eq!(pro_research_topology(&Bm1370BoardProfile::PRO), Ok((13, 5)));
        assert_eq!(
            pro_research_topology(&Bm1370BoardProfile::PLUS),
            Err(WorkGeometryError::UnsupportedTopology)
        );
        assert_eq!(
            pro_research_topology(&Bm1370BoardProfile::XP),
            Err(WorkGeometryError::UnsupportedTopology)
        );
    }
}
